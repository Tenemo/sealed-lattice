import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyProofBackendStatus,
    BallotPrivacyVerification,
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    BallotProofRecord,
    BallotProofStatement,
    ClaimBearingBallotPackage,
    ProtocolDigest,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

import { getBallotPrivacyEncodedShareVectorWidth } from './encoded-share-layout.js';

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyDigest'
>;
type ReceiverKeyProofPayload = Omit<ReceiverKeyProof, 'receiverKeyProofRoot'>;
type ReceiverPayloadCiphertextPayload = Pick<
    ReceiverPayload,
    | 'ceremonyId'
    | 'manifestDigest'
    | 'payloadContextDigest'
    | 'receiverEncryptionProfileDigest'
    | 'receiverIdentity'
    | 'receiverPublicKeyDigest'
    | 'receiverRosterPosition'
    | 'ciphertextBodyDigest'
>;
type ReceiverPayloadPayload = Omit<ReceiverPayload, 'receiverPayloadDigest'>;
type ShareCommitmentPayload = Omit<ShareCommitment, 'shareCommitmentDigest'>;
type BallotProofStatementPayload = Omit<
    BallotProofStatement,
    'ballotProofStatementDigest'
>;
type BallotProofRecordPayload = Omit<
    BallotProofRecord,
    'ballotProofRecordDigest'
>;
type BallotProofComponentProofRecordPayload = Omit<
    BallotProofComponentProofRecord,
    'componentProofRecordDigest'
>;
type BallotProofComponentProofBundlePayload = Omit<
    BallotProofComponentProofBundle,
    'componentProofBundleDigest'
>;
type ReceiverEncryptionPublicKeyInput = Omit<
    ReceiverEncryptionPublicKey,
    'objectType' | 'objectVersion' | 'receiverPublicKeyDigest'
>;
type ReceiverKeyProofInput = Omit<
    ReceiverKeyProof,
    'objectType' | 'objectVersion' | 'receiverKeyProofRoot'
>;
type ReceiverPayloadInput = Omit<
    ReceiverPayload,
    | 'objectType'
    | 'objectVersion'
    | 'receiverPayloadCiphertextRoot'
    | 'receiverPayloadDigest'
>;
type ShareCommitmentInput = Omit<
    ShareCommitment,
    'objectType' | 'objectVersion' | 'shareCommitmentDigest'
>;
export type BallotProofComponentProofVerificationInput = {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementDigest?: ProtocolDigest;
    readonly proofBytesHex: string;
    readonly proofEncoding: unknown;
    readonly proofParameterSet: unknown;
    readonly proofStatement?: unknown;
    readonly proofStatementFormat:
        | 'dense-polynomial-matrix-linear-proof-v1'
        | 'sparse-polynomial-matrix-linear-proof-v1'
        | 'structured-module-lwe-linear-proof-v1'
        | 'public-zero-witness-binding-check-v1';
    readonly publicRandomnessHex: string;
    readonly statementDigest: ProtocolDigest;
};
type UnknownObject = Readonly<Record<string, unknown>>;
type ClaimBearingBallotPackageVerificationShell = ClaimBearingBallotPackage & {
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
    readonly proofBytesHex?: string;
};

const unavailableProofBackendMessage =
    'Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.';
const protocolDigestPattern = /^[a-f0-9]{128}$/u;
const proofBytesHexPattern = /^(?:[a-f0-9]{2})+$/u;
const proofBytesHexAllowEmptyPattern = /^(?:[a-f0-9]{2})*$/u;
const unsignedDecimalStringPattern = /^(?:0|[1-9][0-9]*)$/u;
const shareCommitmentModuleRank = 4;
const shareCommitmentModuleDegree = 256;
const shareCommitmentModulus = 18_446_744_069_414_584_321n;
const requiredBallotProofComponentIds = [
    'score-and-shamir-field-component',
    'payload-plaintext-field-component',
    'share-commitment-component',
    'receiver-encryption-component',
    'receiver-key-binding-component',
] as const satisfies readonly BallotProofComponentId[];
const allowedBallotProofComponentStatementFormats = new Set<
    BallotProofComponentProofVerificationInput['proofStatementFormat']
>([
    'dense-polynomial-matrix-linear-proof-v1',
    'sparse-polynomial-matrix-linear-proof-v1',
    'structured-module-lwe-linear-proof-v1',
    'public-zero-witness-binding-check-v1',
]);
type BallotProofComponentProofBytesAvailability =
    | 'available-for-small-dense-oracle'
    | 'requires-sparse-proof-statement'
    | 'requires-structured-proof-statement'
    | 'public-zero-witness-binding-check';
type BallotProofComponentProofPolicy = {
    readonly proofBytesAvailability: BallotProofComponentProofBytesAvailability;
    readonly proofBytesMustBeEmpty: boolean;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
};
const ballotProofComponentProofPolicyById = {
    'score-and-shamir-field-component': {
        proofBytesAvailability: 'available-for-small-dense-oracle',
        proofBytesMustBeEmpty: false,
        proofStatementFormat: 'dense-polynomial-matrix-linear-proof-v1',
    },
    'payload-plaintext-field-component': {
        proofBytesAvailability: 'requires-sparse-proof-statement',
        proofBytesMustBeEmpty: false,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
    },
    'share-commitment-component': {
        proofBytesAvailability: 'requires-sparse-proof-statement',
        proofBytesMustBeEmpty: false,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
    },
    'receiver-encryption-component': {
        proofBytesAvailability: 'requires-structured-proof-statement',
        proofBytesMustBeEmpty: false,
        proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
    },
    'receiver-key-binding-component': {
        proofBytesAvailability: 'public-zero-witness-binding-check',
        proofBytesMustBeEmpty: true,
        proofStatementFormat: 'public-zero-witness-binding-check-v1',
    },
} as const satisfies Record<
    BallotProofComponentId,
    BallotProofComponentProofPolicy
>;

const requiredLazerPortComponents = [
    'generated linear proof parameters from lin-codegen.sage',
    'portable polynomial ring arithmetic for Z_q[X]/(X^d + 1)',
    'portable polynomial vector and matrix arithmetic',
    'sparse polynomial vector and matrix arithmetic',
    'ABDLop commitment key generation, commitment, and commitment hashing',
    'linear relation statement mapping for A*w + t = 0',
    'linear witness decomposition into short and message coordinates',
    'tbox proof generation and verification',
    'quadratic-to-linear helper relations used by the tbox backend',
    'proof byte coder and decoder',
    'SHAKE128 transcript and expansion path',
    'rejection sampling and bounded short-vector checks',
    'browser-safe prover randomness source',
] as const;

const upstreamLazerReferenceFiles = [
    'src/lin-proofs.c',
    'src/lnp.c',
    'src/lnp-tbox.c',
    'src/lnp-quad.c',
    'src/lnp-quad-many.c',
    'src/lnp-quad-eval.c',
    'src/abdlop.c',
    'src/poly.c',
    'src/polyvec.c',
    'src/polymat.c',
    'src/spolyvec.c',
    'src/spolymat.c',
    'src/coder.c',
    'src/rejection.c',
    'src/rng.c',
    'src/shake128.c',
    'scripts/lin-codegen.sage',
] as const;

export const describeBallotPrivacyProofBackend =
    (): BallotPrivacyProofBackendStatus => ({
        backendName: 'LaZer-style linear lattice proof backend',
        backendAvailable: false,
        upstreamReference: 'lazer-crypto/lazer',
        upstreamDirectDependencyUsableInBrowser: false,
        portableRustWasmPortRequired: true,
        requiredComponents: requiredLazerPortComponents,
        upstreamReferenceFiles: upstreamLazerReferenceFiles,
        blockedReason: unavailableProofBackendMessage,
    });

type BallotProofStatementInput = Omit<
    BallotProofStatement,
    | 'objectType'
    | 'objectVersion'
    | 'ballotProofStatementDigest'
    | 'challengeDomainDigest'
    | 'shareVectorWidth'
> & {
    readonly challengeDomainLabel?: string;
};

const deriveReceiverEncryptionPublicKeyDigest = (
    publicKey: ReceiverEncryptionPublicKeyPayload,
): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', publicKey);

const deriveReceiverKeyProofRoot = (
    receiverKeyProof: ReceiverKeyProofPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyProofRoot', receiverKeyProof);

const deriveReceiverPayloadCiphertextRoot = (
    receiverPayload: ReceiverPayloadCiphertextPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverPayloadCiphertextRoot', receiverPayload);

const deriveReceiverPayloadDigest = (
    receiverPayload: ReceiverPayloadPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverPayloadDigest', receiverPayload);

const deriveShareCommitmentDigest = (
    shareCommitment: ShareCommitmentPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ShareCommitmentDigest', shareCommitment);

const deriveBallotProofStatementDigest = (
    statement: BallotProofStatementPayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotProofStatementDigest', statement);

const deriveBallotProofRecordDigest = (
    proofRecord: BallotProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotProofRecordDigest', proofRecord);

const deriveBallotProofComponentProofRecordDigest = (
    proofRecord: BallotProofComponentProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofRecord,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveBallotProofComponentProofBundleDigest = (
    proofBundle: BallotProofComponentProofBundlePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofBundle,
        purpose: 'ballot-proof-component-proof-bundle-v1',
    });

export const deriveProofBytesDigest = (input: {
    readonly allowEmpty?: boolean;
    readonly proofBytesHex: string;
}): ProtocolDigest => {
    const proofBytesPattern =
        input.allowEmpty === true
            ? proofBytesHexAllowEmptyPattern
            : proofBytesHexPattern;
    if (!proofBytesPattern.test(input.proofBytesHex)) {
        throw new RangeError(
            input.allowEmpty === true
                ? 'Proof bytes must be lowercase hexadecimal bytes.'
                : 'Proof bytes must be non-empty lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolDigest('ProofBytesDigest', {
        objectType: 'ProofBytes',
        objectVersion: 1,
        proofBytesHex: input.proofBytesHex,
        proofSizeBytes: input.proofBytesHex.length / 2,
    });
};

export const deriveBallotProofComponentProofRoot = (input: {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementDigest?: ProtocolDigest;
    readonly componentStatementDigest: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest: ProtocolDigest;
    readonly proofParameterSetDigest: ProtocolDigest;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
    readonly publicRandomnessDigest: ProtocolDigest;
    readonly statementDigest: ProtocolDigest;
}): ProtocolDigest => {
    const payload: Record<string, unknown> = {
        componentId: input.componentId,
        componentStatementDigest: input.componentStatementDigest,
        proofBytesDigest: input.proofBytesDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        proofStatementFormat: input.proofStatementFormat,
        publicRandomnessDigest: input.publicRandomnessDigest,
        purpose: 'ballot-proof-component-proof-root-v1',
        statementDigest: input.statementDigest,
    };
    if (input.componentProofStatementDigest !== undefined) {
        payload.componentProofStatementDigest =
            input.componentProofStatementDigest;
    }

    return deriveProtocolDigest('ChallengeDomainDigest', payload);
};

export const deriveReceiverKeyProofEncodingProfileDigest = (input: {
    readonly proofEncoding: unknown;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        proofEncoding: input.proofEncoding,
        purpose: 'receiver-key-linear-proof-encoding-profile-v1',
    });

export const deriveReceiverKeyProofParameterSetDigest = (input: {
    readonly parameterSet: unknown;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        parameterSet: input.parameterSet,
        purpose: 'receiver-key-linear-proof-parameter-set-v1',
    });

export const deriveReceiverKeyProofPublicRandomnessDigest = (input: {
    readonly publicRandomnessHex: string;
}): ProtocolDigest => {
    if (!/^[a-f0-9]{64}$/u.test(input.publicRandomnessHex)) {
        throw new RangeError(
            'Receiver-key proof public randomness must be 32 lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolDigest('ChallengeDomainDigest', {
        publicRandomnessHex: input.publicRandomnessHex,
        purpose: 'receiver-key-linear-proof-public-randomness-v1',
    });
};

export const deriveBallotProofEncodingProfileDigest = (input: {
    readonly proofEncoding: unknown;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        proofEncoding: input.proofEncoding,
        purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
    });

export const deriveBallotProofParameterSetDigest = (input: {
    readonly parameterSet: unknown;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        parameterSet: input.parameterSet,
        purpose: 'ballot-proof-linear-proof-parameter-set-v1',
    });

export const deriveBallotProofPublicRandomnessDigest = (input: {
    readonly publicRandomnessHex: string;
}): ProtocolDigest => {
    if (!/^[a-f0-9]{64}$/u.test(input.publicRandomnessHex)) {
        throw new RangeError(
            'Ballot proof public randomness must be 32 lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolDigest('ChallengeDomainDigest', {
        publicRandomnessHex: input.publicRandomnessHex,
        purpose: 'ballot-proof-linear-proof-public-randomness-v1',
    });
};

const deriveBallotProofChallengeDigest = (input: {
    readonly statement: BallotProofStatement;
    readonly backendStatementDigest?: ProtocolDigest;
    readonly componentBundleStatementDigest?: ProtocolDigest;
    readonly componentProofBundleDigest?: ProtocolDigest;
    readonly relationStatementDigest: ProtocolDigest;
    readonly linearStatementDigest?: ProtocolDigest;
    readonly statementMatrixDigest?: ProtocolDigest;
    readonly targetVectorDigest?: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest?: ProtocolDigest;
    readonly proofParameterSetDigest?: ProtocolDigest;
    readonly publicRandomnessDigest?: ProtocolDigest;
}): ProtocolDigest => {
    const challengePayload: Record<string, unknown> = {
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        challengeDomainDigest: input.statement.challengeDomainDigest,
        proofBytesDigest: input.proofBytesDigest,
        proofRoot: input.proofRoot,
        relationStatementDigest: input.relationStatementDigest,
    };

    for (const [fieldName, digestValue] of Object.entries({
        backendStatementDigest: input.backendStatementDigest,
        componentBundleStatementDigest: input.componentBundleStatementDigest,
        componentProofBundleDigest: input.componentProofBundleDigest,
        linearStatementDigest: input.linearStatementDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        publicRandomnessDigest: input.publicRandomnessDigest,
        statementMatrixDigest: input.statementMatrixDigest,
        targetVectorDigest: input.targetVectorDigest,
    })) {
        if (digestValue !== undefined) {
            challengePayload[fieldName] = digestValue;
        }
    }

    return deriveProtocolDigest('ChallengeDomainDigest', challengePayload);
};

const hasOwnProperty = (value: object, key: PropertyKey): boolean =>
    Object.prototype.hasOwnProperty.call(value, key);

const omitProperty = <InputValue extends object, Key extends keyof InputValue>(
    value: InputValue,
    propertyKey: Key,
): Omit<InputValue, Key> => {
    const { [propertyKey]: omittedValue, ...remainingProperties } = value;
    void omittedValue;

    return remainingProperties;
};

const isUnknownObject = (value: unknown): value is UnknownObject =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const omitUnknownObjectProperty = (
    value: UnknownObject,
    propertyKey: string,
): UnknownObject => {
    const remainingProperties: Record<string, unknown> = { ...value };
    delete remainingProperties[propertyKey];

    return remainingProperties;
};

type ReceiverReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
};

const createReceiverReferenceKey = (
    receiverReference: ReceiverReference,
): string =>
    `${receiverReference.receiverRosterPosition}:${receiverReference.receiverIdentity}`;

const collectReceiverReferenceRefusals = (input: {
    readonly references: readonly ReceiverReference[];
    readonly objectDigest: ProtocolDigest;
    readonly label: string;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const seenReceiverReferences = new Set<string>();

    for (const receiverReference of input.references) {
        const receiverReferenceKey =
            createReceiverReferenceKey(receiverReference);
        if (
            receiverReference.receiverIdentity.length === 0 ||
            !Number.isSafeInteger(receiverReference.receiverRosterPosition) ||
            receiverReference.receiverRosterPosition <= 0
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `${input.label} contains an invalid receiver identity or roster position.`,
                    input.objectDigest,
                ),
            );
            continue;
        }
        if (seenReceiverReferences.has(receiverReferenceKey)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `${input.label} contains a duplicate receiver reference.`,
                    input.objectDigest,
                ),
            );
        }
        seenReceiverReferences.add(receiverReferenceKey);
    }

    return refusedObjects;
};

export const createReceiverEncryptionPublicKeyShell = (
    input: ReceiverEncryptionPublicKeyInput,
): ReceiverEncryptionPublicKey => {
    const publicKeyPayload: ReceiverEncryptionPublicKeyPayload = {
        objectType: 'ReceiverEncryptionPublicKey',
        objectVersion: 1,
        ...input,
    };

    return {
        ...publicKeyPayload,
        receiverPublicKeyDigest:
            deriveReceiverEncryptionPublicKeyDigest(publicKeyPayload),
    };
};

export const createReceiverKeyProofShell = (
    input: ReceiverKeyProofInput,
): ReceiverKeyProof => {
    const receiverKeyProofPayload: ReceiverKeyProofPayload = {
        objectType: 'ReceiverKeyProof',
        objectVersion: 1,
        ...input,
    };

    return {
        ...receiverKeyProofPayload,
        receiverKeyProofRoot: deriveReceiverKeyProofRoot(
            receiverKeyProofPayload,
        ),
    };
};

export const createReceiverPayloadShell = (
    input: ReceiverPayloadInput,
): ReceiverPayload => {
    const ciphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        payloadContextDigest: input.payloadContextDigest,
        receiverEncryptionProfileDigest: input.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverIdentity,
        receiverPublicKeyDigest: input.receiverPublicKeyDigest,
        receiverRosterPosition: input.receiverRosterPosition,
        ciphertextBodyDigest: input.ciphertextBodyDigest,
    });
    const receiverPayloadPayload: ReceiverPayloadPayload = {
        objectType: 'ReceiverPayload',
        objectVersion: 1,
        ...input,
        receiverPayloadCiphertextRoot: ciphertextRoot,
    };

    return {
        ...receiverPayloadPayload,
        receiverPayloadDigest: deriveReceiverPayloadDigest(
            receiverPayloadPayload,
        ),
    };
};

export const createShareCommitmentShell = (
    input: ShareCommitmentInput,
): ShareCommitment => {
    const shareCommitmentPayload: ShareCommitmentPayload = {
        objectType: 'ShareCommitment',
        objectVersion: 1,
        ...input,
    };

    return {
        ...shareCommitmentPayload,
        shareCommitmentDigest: deriveShareCommitmentDigest(
            shareCommitmentPayload,
        ),
    };
};

export const buildBallotProofStatement = (
    input: BallotProofStatementInput,
): BallotProofStatement => {
    const challengeDomainDigest = deriveProtocolDigest(
        'ChallengeDomainDigest',
        {
            ballotProofProfileDigest: input.ballotProofProfileDigest,
            aggregateInputEncodingProfileDigest:
                input.aggregateInputEncodingProfileDigest,
            challengeDomainLabel:
                input.challengeDomainLabel ??
                'sealed.vote/v1/ballot-proof/challenge',
            ballotScoreEncodingProfileDigest:
                input.ballotScoreEncodingProfileDigest,
            ballotShareLayoutProfileDigest:
                input.ballotShareLayoutProfileDigest,
            encodedAggregateLayoutDigest: input.encodedAggregateLayoutDigest,
            encodedShareVectorLayoutDigest:
                input.encodedShareVectorLayoutDigest,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfileDigest,
            scoreMembershipProfileDigest: input.scoreMembershipProfileDigest,
            shareCommitmentMessageBoundCertDigest:
                input.shareCommitmentMessageBoundCertDigest,
            shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        },
    );
    const shareVectorWidth = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );
    const statementPayload: BallotProofStatementPayload = {
        objectType: 'BallotProofStatement',
        objectVersion: 1,
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        pollSpecDigest: input.pollSpecDigest,
        thresholdProfileDigest: input.thresholdProfileDigest,
        duplicateBallotPolicyDigest: input.duplicateBallotPolicyDigest,
        scoreDomainDigest: input.scoreDomainDigest,
        tiePolicyDigest: input.tiePolicyDigest,
        topOptionCount: input.topOptionCount,
        optionCount: input.optionCount,
        shareVectorWidth,
        voterIdentityDigest: input.voterIdentityDigest,
        voterRosterPosition: input.voterRosterPosition,
        voterSigningKeyDigest: input.voterSigningKeyDigest,
        actionContextDigest: input.actionContextDigest,
        rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
        receiverKeyRoot: input.receiverKeyRoot,
        receiverKeyProofRoot: input.receiverKeyProofRoot,
        receiverPublicKeys: input.receiverPublicKeys,
        receiverPayloads: input.receiverPayloads,
        shareCommitments: input.shareCommitments,
        shareCommitmentProfileDigest: input.shareCommitmentProfileDigest,
        receiverEncryptionProfileDigest: input.receiverEncryptionProfileDigest,
        ballotProofProfileDigest: input.ballotProofProfileDigest,
        scoreMembershipProfileDigest: input.scoreMembershipProfileDigest,
        ballotScoreEncodingProfileDigest:
            input.ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest: input.ballotShareLayoutProfileDigest,
        aggregateInputEncodingProfileDigest:
            input.aggregateInputEncodingProfileDigest,
        encodedShareVectorLayoutDigest: input.encodedShareVectorLayoutDigest,
        encodedAggregateLayoutDigest: input.encodedAggregateLayoutDigest,
        shareCommitmentMessageBoundCertDigest:
            input.shareCommitmentMessageBoundCertDigest,
        ballotPackageDigest: input.ballotPackageDigest,
        challengeDomainDigest,
    };

    return {
        ...statementPayload,
        ballotProofStatementDigest:
            deriveBallotProofStatementDigest(statementPayload),
    };
};

export const createBallotProofRecordShell = (input: {
    readonly statement: BallotProofStatement;
    readonly backendStatementDigest?: ProtocolDigest;
    readonly componentBundleStatementDigest?: ProtocolDigest;
    readonly componentProofBundleDigest?: ProtocolDigest;
    readonly relationStatementDigest: ProtocolDigest;
    readonly linearStatementDigest?: ProtocolDigest;
    readonly statementMatrixDigest?: ProtocolDigest;
    readonly targetVectorDigest?: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest?: ProtocolDigest;
    readonly proofParameterSetDigest?: ProtocolDigest;
    readonly proofSizeBytes: number;
    readonly publicRandomnessDigest?: ProtocolDigest;
}): BallotProofRecord => {
    const challengeDigest = deriveBallotProofChallengeDigest({
        statement: input.statement,
        backendStatementDigest: input.backendStatementDigest,
        componentBundleStatementDigest: input.componentBundleStatementDigest,
        componentProofBundleDigest: input.componentProofBundleDigest,
        relationStatementDigest: input.relationStatementDigest,
        linearStatementDigest: input.linearStatementDigest,
        statementMatrixDigest: input.statementMatrixDigest,
        targetVectorDigest: input.targetVectorDigest,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        publicRandomnessDigest: input.publicRandomnessDigest,
    });
    const proofRecordPayload: BallotProofRecordPayload = {
        objectType: 'BallotProofRecord',
        objectVersion: 1,
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        ...(input.backendStatementDigest === undefined
            ? {}
            : { backendStatementDigest: input.backendStatementDigest }),
        ...(input.componentBundleStatementDigest === undefined
            ? {}
            : {
                  componentBundleStatementDigest:
                      input.componentBundleStatementDigest,
              }),
        ...(input.componentProofBundleDigest === undefined
            ? {}
            : {
                  componentProofBundleDigest: input.componentProofBundleDigest,
              }),
        relationStatementDigest: input.relationStatementDigest,
        ...(input.linearStatementDigest === undefined
            ? {}
            : { linearStatementDigest: input.linearStatementDigest }),
        ...(input.statementMatrixDigest === undefined
            ? {}
            : { statementMatrixDigest: input.statementMatrixDigest }),
        ...(input.targetVectorDigest === undefined
            ? {}
            : { targetVectorDigest: input.targetVectorDigest }),
        ballotProofProfileDigest: input.statement.ballotProofProfileDigest,
        proofBackend: 'LaZerStyleLocalLatticeRelation',
        challengeDigest,
        proofRoot: input.proofRoot,
        proofBytesDigest: input.proofBytesDigest,
        ...(input.proofEncodingProfileDigest === undefined
            ? {}
            : {
                  proofEncodingProfileDigest: input.proofEncodingProfileDigest,
              }),
        ...(input.proofParameterSetDigest === undefined
            ? {}
            : { proofParameterSetDigest: input.proofParameterSetDigest }),
        proofSizeBytes: input.proofSizeBytes,
        ...(input.publicRandomnessDigest === undefined
            ? {}
            : { publicRandomnessDigest: input.publicRandomnessDigest }),
    };

    return {
        ...proofRecordPayload,
        ballotProofRecordDigest:
            deriveBallotProofRecordDigest(proofRecordPayload),
    };
};

const createUnavailableProofBackendVerification = (
    operation: string,
    objectDigest?: ProtocolDigest,
): BallotPrivacyVerification => {
    const refusedObjects: RefusalRecord[] = [
        createRefusal(
            'OperationUnavailable',
            `${operation}: ${unavailableProofBackendMessage}`,
            objectDigest,
        ),
    ];

    return {
        ok: false,
        backendAvailable: false,
        backendStatus: describeBallotPrivacyProofBackend(),
        statusLabels: [],
        acceptedDigests: [],
        refusedObjects,
        unresolvedReason: 'OperationUnavailable',
    };
};

const createBallotPrivacyStructuralRejection = (
    refusedObjects: readonly RefusalRecord[],
): BallotPrivacyVerification => ({
    ok: false,
    backendAvailable: false,
    backendStatus: describeBallotPrivacyProofBackend(),
    statusLabels: [],
    acceptedDigests: [],
    refusedObjects,
    unresolvedReason: refusedObjects[0]?.code ?? 'BallotPackageInvalid',
});

const digestForInvalidComponentInput = (): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'invalid-ballot-proof-component-input-v1',
    });

const collectReceiverKeyProofStructuralRefusals = (
    receiverKeyProof: ReceiverKeyProof,
    proofBytesHex?: string,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const receiverKeyProofPayload = omitProperty(
        receiverKeyProof,
        'receiverKeyProofRoot',
    );
    const expectedReceiverKeyProofRoot = deriveReceiverKeyProofRoot(
        receiverKeyProofPayload,
    );

    if (
        receiverKeyProof.objectType !== 'ReceiverKeyProof' ||
        receiverKeyProof.objectVersion !== 1 ||
        receiverKeyProof.proofBackend !== 'LaZerStyleLocalLatticeRelation' ||
        !protocolDigestPattern.test(receiverKeyProof.proofRoot) ||
        (receiverKeyProof.backendStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.backendStatementDigest,
            )) ||
        (receiverKeyProof.linearStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.linearStatementDigest,
            )) ||
        (receiverKeyProof.proofBytesDigest !== undefined &&
            !protocolDigestPattern.test(receiverKeyProof.proofBytesDigest)) ||
        (receiverKeyProof.proofEncodingProfileDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.proofEncodingProfileDigest,
            )) ||
        (receiverKeyProof.proofParameterSetDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.proofParameterSetDigest,
            )) ||
        (receiverKeyProof.publicRandomnessDigest !== undefined &&
            !protocolDigestPattern.test(
                receiverKeyProof.publicRandomnessDigest,
            )) ||
        (receiverKeyProof.proofSizeBytes !== undefined &&
            (!Number.isSafeInteger(receiverKeyProof.proofSizeBytes) ||
                receiverKeyProof.proofSizeBytes <= 0))
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof shell has an invalid canonical shape.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }
    const proofMetadataFieldNames = [
        'linearStatementDigest',
        'proofBytesDigest',
        'proofEncodingProfileDigest',
        'proofParameterSetDigest',
        'proofSizeBytes',
        'publicRandomnessDigest',
    ] as const;
    const presentProofMetadataFieldCount = proofMetadataFieldNames.filter(
        (fieldName) => receiverKeyProof[fieldName] !== undefined,
    ).length;
    if (
        presentProofMetadataFieldCount > 0 &&
        presentProofMetadataFieldCount !== proofMetadataFieldNames.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof byte metadata must be complete when any proof-byte field is present.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }
    if (proofBytesHex !== undefined) {
        if (receiverKeyProof.proofBytesDigest === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver key proof bytes require a proof-byte-bearing receiver key proof record.',
                    receiverKeyProof.receiverKeyProofRoot,
                ),
            );
        } else if (!proofBytesHexPattern.test(proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver key proof bytes must be non-empty lowercase hexadecimal bytes.',
                    receiverKeyProof.receiverKeyProofRoot,
                ),
            );
        } else {
            const proofSizeBytes = proofBytesHex.length / 2;
            const proofBytesDigest = deriveProofBytesDigest({
                proofBytesHex,
            });
            if (proofSizeBytes !== receiverKeyProof.proofSizeBytes) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Receiver key proof byte length does not match the proof record.',
                        receiverKeyProof.receiverKeyProofRoot,
                    ),
                );
            }
            if (proofBytesDigest !== receiverKeyProof.proofBytesDigest) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Receiver key proof bytes do not match the proof record digest.',
                        receiverKeyProof.receiverKeyProofRoot,
                    ),
                );
            }
        }
    }
    if (
        receiverKeyProof.receiverKeyProofRoot !== expectedReceiverKeyProofRoot
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key proof root does not match its canonical payload.',
                receiverKeyProof.receiverKeyProofRoot,
            ),
        );
    }

    return refusedObjects;
};

const collectBallotProofStructuralRefusals = (
    statement: BallotProofStatement,
    ballotProof: BallotProofRecord,
    proofBytesHex?: string,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const statementPayload = omitProperty(
        statement,
        'ballotProofStatementDigest',
    );
    const expectedStatementDigest =
        deriveBallotProofStatementDigest(statementPayload);
    const proofPayload = omitProperty(ballotProof, 'ballotProofRecordDigest');
    const expectedProofRecordDigest =
        deriveBallotProofRecordDigest(proofPayload);
    const expectedChallengeDigest = deriveBallotProofChallengeDigest({
        backendStatementDigest: ballotProof.backendStatementDigest,
        componentBundleStatementDigest:
            ballotProof.componentBundleStatementDigest,
        componentProofBundleDigest: ballotProof.componentProofBundleDigest,
        proofBytesDigest: ballotProof.proofBytesDigest,
        proofEncodingProfileDigest: ballotProof.proofEncodingProfileDigest,
        proofParameterSetDigest: ballotProof.proofParameterSetDigest,
        proofRoot: ballotProof.proofRoot,
        publicRandomnessDigest: ballotProof.publicRandomnessDigest,
        relationStatementDigest: ballotProof.relationStatementDigest,
        linearStatementDigest: ballotProof.linearStatementDigest,
        statementMatrixDigest: ballotProof.statementMatrixDigest,
        statement,
        targetVectorDigest: ballotProof.targetVectorDigest,
    });

    if (
        statement.objectType !== 'BallotProofStatement' ||
        statement.objectVersion !== 1 ||
        statement.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(statement.optionCount)
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement has an invalid canonical shape.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    if (statement.ballotProofStatementDigest !== expectedStatementDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement digest does not match its canonical payload.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    refusedObjects.push(
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-key references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.receiverPublicKeys,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof receiver-payload references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.receiverPayloads,
        }),
        ...collectReceiverReferenceRefusals({
            label: 'Ballot proof share-commitment references',
            objectDigest: statement.ballotProofStatementDigest,
            references: statement.shareCommitments,
        }),
    );
    if (
        statement.receiverPublicKeys.length === 0 ||
        statement.receiverPublicKeys.length !==
            statement.receiverPayloads.length ||
        statement.receiverPublicKeys.length !==
            statement.shareCommitments.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof statement must bind the same non-empty receiver set across keys, payloads, and commitments.',
                statement.ballotProofStatementDigest,
            ),
        );
    }
    if (
        ballotProof.objectType !== 'BallotProofRecord' ||
        ballotProof.objectVersion !== 1 ||
        ballotProof.proofBackend !== 'LaZerStyleLocalLatticeRelation' ||
        (ballotProof.backendStatementDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.backendStatementDigest)) ||
        (ballotProof.componentBundleStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.componentBundleStatementDigest,
            )) ||
        (ballotProof.componentProofBundleDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.componentProofBundleDigest,
            )) ||
        !protocolDigestPattern.test(ballotProof.relationStatementDigest) ||
        (ballotProof.linearStatementDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.linearStatementDigest)) ||
        (ballotProof.statementMatrixDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.statementMatrixDigest)) ||
        (ballotProof.targetVectorDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.targetVectorDigest)) ||
        !protocolDigestPattern.test(ballotProof.proofRoot) ||
        !protocolDigestPattern.test(ballotProof.proofBytesDigest) ||
        (ballotProof.proofEncodingProfileDigest !== undefined &&
            !protocolDigestPattern.test(
                ballotProof.proofEncodingProfileDigest,
            )) ||
        (ballotProof.proofParameterSetDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.proofParameterSetDigest)) ||
        (ballotProof.publicRandomnessDigest !== undefined &&
            !protocolDigestPattern.test(ballotProof.publicRandomnessDigest)) ||
        !Number.isSafeInteger(ballotProof.proofSizeBytes) ||
        ballotProof.proofSizeBytes <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record has an invalid canonical shape.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    const proofBackendMetadataFieldNames = [
        'backendStatementDigest',
        'linearStatementDigest',
        'statementMatrixDigest',
        'targetVectorDigest',
        'proofEncodingProfileDigest',
        'proofParameterSetDigest',
        'publicRandomnessDigest',
    ] as const;
    const presentProofBackendMetadataFieldCount =
        proofBackendMetadataFieldNames.filter(
            (fieldName) => ballotProof[fieldName] !== undefined,
        ).length;
    if (
        presentProofBackendMetadataFieldCount > 0 &&
        presentProofBackendMetadataFieldCount !==
            proofBackendMetadataFieldNames.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof backend metadata must be complete when any backend proof field is present.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (
        ballotProof.ballotProofStatementDigest !==
        statement.ballotProofStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied statement.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (
        ballotProof.ballotProofProfileDigest !==
        statement.ballotProofProfileDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the statement proof profile.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (ballotProof.challengeDigest !== expectedChallengeDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof challenge digest does not match the statement and proof roots.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (ballotProof.ballotProofRecordDigest !== expectedProofRecordDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record digest does not match its canonical payload.',
                ballotProof.ballotProofRecordDigest,
            ),
        );
    }
    if (proofBytesHex !== undefined) {
        if (!proofBytesHexPattern.test(proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof bytes must be non-empty lowercase hexadecimal bytes.',
                    ballotProof.ballotProofRecordDigest,
                ),
            );
        } else {
            const proofSizeBytes = proofBytesHex.length / 2;
            const proofBytesDigest = deriveProofBytesDigest({
                proofBytesHex,
            });
            if (proofSizeBytes !== ballotProof.proofSizeBytes) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof byte length does not match the proof record.',
                        ballotProof.ballotProofRecordDigest,
                    ),
                );
            }
            if (proofBytesDigest !== ballotProof.proofBytesDigest) {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        'Ballot proof bytes do not match the proof record digest.',
                        ballotProof.ballotProofRecordDigest,
                    ),
                );
            }
        }
    }

    return refusedObjects;
};

const deriveSuppliedComponentProofStatementDigest = (input: {
    readonly proofStatement: UnknownObject;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
}): { readonly digest?: ProtocolDigest; readonly digestFieldName?: string } => {
    const objectType = input.proofStatement.objectType;

    if (
        input.proofStatementFormat ===
            'dense-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofLinearProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose: 'ballot-proof-linear-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        input.proofStatementFormat ===
            'sparse-polynomial-matrix-linear-proof-v1' &&
        objectType === 'BallotProofSparseComponentLinearProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1' &&
        objectType === 'BallotProofStructuredReceiverEncryptionProofStatement'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'statementDigest',
                ),
                purpose:
                    'ballot-proof-structured-receiver-encryption-proof-statement-v1',
            }),
            digestFieldName: 'statementDigest',
        };
    }
    if (
        (input.proofStatementFormat ===
            'structured-module-lwe-linear-proof-v1' ||
            input.proofStatementFormat ===
                'public-zero-witness-binding-check-v1') &&
        objectType === 'BallotProofComponentProofStatementPlan'
    ) {
        return {
            digest: deriveProtocolDigest('ChallengeDomainDigest', {
                payload: omitUnknownObjectProperty(
                    input.proofStatement,
                    'componentProofStatementDigest',
                ),
                purpose: 'ballot-proof-component-proof-statement-plan-v1',
            }),
            digestFieldName: 'componentProofStatementDigest',
        };
    }

    return {};
};

const isProtocolDigestValue = (value: unknown): value is ProtocolDigest =>
    typeof value === 'string' && protocolDigestPattern.test(value);

const isUnsignedDecimalString = (value: unknown): value is string =>
    typeof value === 'string' && unsignedDecimalStringPattern.test(value);

const isNonNegativeSafeInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

const isPositiveSafeInteger = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

const isStringArray = (value: unknown): value is readonly string[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => typeof entry === 'string');
};

const isProtocolDigestArray = (
    value: unknown,
): value is readonly ProtocolDigest[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => isProtocolDigestValue(entry));
};

const isNonNegativeIntegerArray = (
    value: unknown,
): value is readonly number[] => {
    if (!Array.isArray(value)) {
        return false;
    }

    return value.every((entry: unknown) => isNonNegativeSafeInteger(entry));
};

const collectComponentProofStatementPlanShapeRefusals = (input: {
    readonly expectedComponentId: BallotProofComponentId;
    readonly proofRecordDigest: ProtocolDigest;
    readonly proofStatement: UnknownObject;
}): readonly RefusalRecord[] => {
    const componentProofPolicy =
        ballotProofComponentProofPolicyById[input.expectedComponentId];
    if (
        input.proofStatement.objectType !==
        'BallotProofComponentProofStatementPlan'
    ) {
        return [];
    }

    const rowBatchNames = input.proofStatement.rowBatchNames;
    const rowBatchMatrixDigests = input.proofStatement.rowBatchMatrixDigests;
    const rowBatchTargetVectorDigests =
        input.proofStatement.rowBatchTargetVectorDigests;
    const rowBatchTermCounts = input.proofStatement.rowBatchTermCounts;
    const variableColumnIndices = input.proofStatement.variableColumnIndices;
    const rowBatchCount =
        Array.isArray(rowBatchNames) && rowBatchNames.length > 0
            ? rowBatchNames.length
            : undefined;
    const rowBatchFieldsMatch =
        rowBatchCount !== undefined &&
        Array.isArray(rowBatchMatrixDigests) &&
        rowBatchMatrixDigests.length === rowBatchCount &&
        Array.isArray(rowBatchTargetVectorDigests) &&
        rowBatchTargetVectorDigests.length === rowBatchCount &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.length === rowBatchCount;
    const commonShapeIsValid =
        input.proofStatement.objectVersion === 1 &&
        input.proofStatement.componentId === input.expectedComponentId &&
        input.proofStatement.proofStatementFormat ===
            componentProofPolicy.proofStatementFormat &&
        input.proofStatement.proofBytesAvailability ===
            componentProofPolicy.proofBytesAvailability &&
        input.proofStatement.proofLoweringStatus === 'explicitRowsAvailable' &&
        input.proofStatement.relation === 'A*w + t = 0' &&
        isUnsignedDecimalString(input.proofStatement.coefficientModulus) &&
        isProtocolDigestValue(input.proofStatement.backendStatementDigest) &&
        isProtocolDigestValue(
            input.proofStatement.componentProofStatementDigest,
        ) &&
        isProtocolDigestValue(input.proofStatement.componentStatementDigest) &&
        isProtocolDigestValue(input.proofStatement.matrixDigest) &&
        isProtocolDigestValue(input.proofStatement.relationStatementDigest) &&
        isProtocolDigestValue(input.proofStatement.targetVectorDigest) &&
        isProtocolDigestArray(rowBatchMatrixDigests) &&
        isStringArray(rowBatchNames) &&
        isProtocolDigestArray(rowBatchTargetVectorDigests) &&
        Array.isArray(rowBatchTermCounts) &&
        rowBatchTermCounts.every(isUnsignedDecimalString) &&
        rowBatchFieldsMatch &&
        isPositiveSafeInteger(input.proofStatement.rowCount) &&
        isNonNegativeSafeInteger(input.proofStatement.variableColumnCount) &&
        isNonNegativeIntegerArray(variableColumnIndices);

    const componentSpecificShapeIsValid = (() => {
        if (
            input.expectedComponentId === 'receiver-encryption-component' &&
            componentProofPolicy.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1'
        ) {
            return (
                input.proofStatement.sourceRingDegree === 256 &&
                input.proofStatement.proofSystemRingDegree === 64 &&
                isUnsignedDecimalString(
                    input.proofStatement.denseCoefficientCount,
                ) &&
                input.proofStatement.sparseTermCount === null &&
                isPositiveSafeInteger(
                    input.proofStatement.structuredCiphertextChunkCount,
                ) &&
                isPositiveSafeInteger(
                    input.proofStatement.structuredReceiverCount,
                ) &&
                isUnsignedDecimalString(
                    input.proofStatement.structuredWitnessTermCount,
                ) &&
                input.proofStatement.structuredWitnessTermCount !== '0' &&
                Number(input.proofStatement.variableColumnCount) > 0 &&
                Array.isArray(variableColumnIndices) &&
                variableColumnIndices.length ===
                    input.proofStatement.variableColumnCount
            );
        }
        if (
            input.expectedComponentId === 'receiver-key-binding-component' &&
            componentProofPolicy.proofStatementFormat ===
                'public-zero-witness-binding-check-v1'
        ) {
            return (
                input.proofStatement.sourceRingDegree === null &&
                input.proofStatement.proofSystemRingDegree === null &&
                input.proofStatement.denseCoefficientCount === null &&
                input.proofStatement.sparseTermCount === null &&
                input.proofStatement.structuredCiphertextChunkCount === null &&
                input.proofStatement.structuredReceiverCount === null &&
                input.proofStatement.structuredWitnessTermCount === null &&
                input.proofStatement.variableColumnCount === 0 &&
                Array.isArray(variableColumnIndices) &&
                variableColumnIndices.length === 0 &&
                Array.isArray(rowBatchTermCounts) &&
                rowBatchTermCounts.every((termCount) => termCount === '0')
            );
        }

        return true;
    })();

    if (!commonShapeIsValid || !componentSpecificShapeIsValid) {
        return [
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement plan for ${input.expectedComponentId} has an invalid canonical shape.`,
                input.proofRecordDigest,
            ),
        ];
    }

    return [];
};

const collectSuppliedComponentProofStatementRefusals = (input: {
    readonly componentProof: BallotProofComponentProofRecord;
    readonly expectedComponentId: BallotProofComponentId;
    readonly proofInput: BallotProofComponentProofVerificationInput;
    readonly proofRecordDigest: ProtocolDigest;
}): readonly RefusalRecord[] => {
    const proofStatement = input.proofInput.proofStatement;
    if (proofStatement === undefined) {
        return [];
    }
    if (!isUnknownObject(proofStatement)) {
        return [
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement object for ${input.expectedComponentId} is malformed.`,
                input.proofRecordDigest,
            ),
        ];
    }

    const refusedObjects: RefusalRecord[] = [];
    refusedObjects.push(
        ...collectComponentProofStatementPlanShapeRefusals({
            expectedComponentId: input.expectedComponentId,
            proofRecordDigest: input.proofRecordDigest,
            proofStatement,
        }),
    );
    const suppliedFormat = proofStatement.proofStatementFormat;
    const suppliedComponentId = proofStatement.componentId;
    const suppliedComponentStatementDigest =
        proofStatement.componentStatementDigest;
    const suppliedStatementDigest = proofStatement.statementDigest;
    const suppliedComponentProofStatementDigest =
        proofStatement.componentProofStatementDigest;
    const derivedStatementDigest = deriveSuppliedComponentProofStatementDigest({
        proofStatement,
        proofStatementFormat: input.proofInput.proofStatementFormat,
    });

    if (derivedStatementDigest.digest === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement object for ${input.expectedComponentId} does not match its declared statement format.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedFormat !== undefined &&
        suppliedFormat !== input.proofInput.proofStatementFormat
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement format for ${input.expectedComponentId} does not match the supplied proof input.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedComponentId !== undefined &&
        suppliedComponentId !== input.expectedComponentId
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} is bound to the wrong component.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        suppliedComponentStatementDigest !== undefined &&
        suppliedComponentStatementDigest !==
            input.componentProof.componentStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} is not bound to the component statement.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digestFieldName === 'statementDigest' &&
        suppliedStatementDigest !== derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement digest for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        derivedStatementDigest.digestFieldName ===
            'componentProofStatementDigest' &&
        suppliedComponentProofStatementDigest !== derivedStatementDigest.digest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement digest for ${input.expectedComponentId} does not match its canonical payload.`,
                input.proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProof.componentProofStatementDigest !== undefined &&
        derivedStatementDigest.digestFieldName ===
            'componentProofStatementDigest' &&
        suppliedComponentProofStatementDigest !==
            input.componentProof.componentProofStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot proof component proof statement for ${input.expectedComponentId} does not match the proof record digest.`,
                input.proofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

function collectBallotProofComponentProofInputRefusals(input: {
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
}): readonly RefusalRecord[] {
    const refusedObjects: RefusalRecord[] = [];
    const proofRecordDigest = input.ballotProof.ballotProofRecordDigest;

    if (input.componentProofInputs === undefined) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Full encoded-score ballot proof verification requires public proof inputs for every component proof.',
                proofRecordDigest,
            ),
        );

        return refusedObjects;
    }
    if (
        input.componentProofInputs.length !==
        requiredBallotProofComponentIds.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof inputs must contain exactly the required components.',
                proofRecordDigest,
            ),
        );
    }

    const proofInputsByComponent = new Map<
        BallotProofComponentId,
        BallotProofComponentProofVerificationInput
    >();
    for (const proofInput of input.componentProofInputs) {
        if (proofInputsByComponent.has(proofInput.componentId)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof component proof inputs contain a duplicate component.',
                    proofRecordDigest,
                ),
            );
        }
        proofInputsByComponent.set(proofInput.componentId, proofInput);
    }

    for (
        let componentIndex = 0;
        componentIndex < requiredBallotProofComponentIds.length;
        componentIndex += 1
    ) {
        const expectedComponentId =
            requiredBallotProofComponentIds[componentIndex];
        const componentProofPolicy =
            ballotProofComponentProofPolicyById[expectedComponentId];
        const componentProof =
            input.componentProofBundle.componentProofs[componentIndex];
        const proofInput = proofInputsByComponent.get(expectedComponentId);
        if (componentProof === undefined || proofInput === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is missing.`,
                    proofRecordDigest,
                ),
            );
            continue;
        }
        if (proofInput.componentId !== componentProof.componentId) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the matching proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.componentProofStatementDigest !== undefined &&
            proofInput.componentProofStatementDigest !==
                componentProof.componentProofStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            !allowedBallotProofComponentStatementFormats.has(
                proofInput.proofStatementFormat,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement format for ${expectedComponentId} is not supported.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofInput.proofStatementFormat !==
            componentProofPolicy.proofStatementFormat
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof statement format for ${expectedComponentId} must be ${componentProofPolicy.proofStatementFormat}.`,
                    proofRecordDigest,
                ),
            );
        }
        const proofBytesPattern = componentProofPolicy.proofBytesMustBeEmpty
            ? proofBytesHexAllowEmptyPattern
            : proofBytesHexPattern;
        if (componentProofPolicy.proofBytesMustBeEmpty) {
            if (proofInput.proofBytesHex !== '') {
                refusedObjects.push(
                    createRefusal(
                        'BallotPackageInvalid',
                        `Ballot proof component proof bytes for ${expectedComponentId} must be empty for the public-zero witness binding check.`,
                        proofRecordDigest,
                    ),
                );
            }
        } else if (!proofBytesHexPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be non-empty lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
            continue;
        }
        if (!proofBytesPattern.test(proofInput.proofBytesHex)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} must be lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
            continue;
        }
        const proofBytesDigest = deriveProofBytesDigest({
            allowEmpty: componentProofPolicy.proofBytesMustBeEmpty,
            proofBytesHex: proofInput.proofBytesHex,
        });
        const proofSizeBytes = proofInput.proofBytesHex.length / 2;
        const proofEncodingProfileDigest =
            deriveBallotProofEncodingProfileDigest({
                proofEncoding: proofInput.proofEncoding,
            });
        const proofParameterSetDigest = deriveBallotProofParameterSetDigest({
            parameterSet: proofInput.proofParameterSet,
        });
        const publicRandomnessDigest = (() => {
            try {
                return deriveBallotProofPublicRandomnessDigest({
                    publicRandomnessHex: proofInput.publicRandomnessHex,
                });
            } catch {
                return undefined;
            }
        })();

        if (proofSizeBytes !== componentProof.proofSizeBytes) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof byte length for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (proofBytesDigest !== componentProof.proofBytesDigest) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof bytes for ${expectedComponentId} do not match the proof record digest.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofEncodingProfileDigest !==
            componentProof.proofEncodingProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof encoding for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofParameterSetDigest !== componentProof.proofParameterSetDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof parameter set for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (publicRandomnessDigest === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} must be 32 lowercase hexadecimal bytes.`,
                    proofRecordDigest,
                ),
            );
        } else if (
            publicRandomnessDigest !== componentProof.publicRandomnessDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component public randomness for ${expectedComponentId} does not match the proof record.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            proofInput.statementDigest !==
            componentProof.componentStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} is not bound to the component statement.`,
                    proofRecordDigest,
                ),
            );
        }
        if (proofInput.proofStatement === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof input for ${expectedComponentId} must supply its public proof statement object.`,
                    proofRecordDigest,
                ),
            );
        }
        const expectedProofRoot = deriveBallotProofComponentProofRoot({
            componentId: expectedComponentId,
            componentProofStatementDigest:
                proofInput.componentProofStatementDigest,
            componentStatementDigest: componentProof.componentStatementDigest,
            proofBytesDigest,
            proofEncodingProfileDigest,
            proofParameterSetDigest,
            proofStatementFormat: proofInput.proofStatementFormat,
            publicRandomnessDigest:
                publicRandomnessDigest ?? digestForInvalidComponentInput(),
            statementDigest: proofInput.statementDigest,
        });
        if (
            publicRandomnessDigest !== undefined &&
            componentProof.proofRoot !== expectedProofRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof root for ${expectedComponentId} does not match the supplied public proof input.`,
                    proofRecordDigest,
                ),
            );
        }
        refusedObjects.push(
            ...collectSuppliedComponentProofStatementRefusals({
                componentProof,
                expectedComponentId,
                proofInput,
                proofRecordDigest,
            }),
        );
    }

    return refusedObjects;
}

const collectBallotProofComponentProofBundleRefusals = (input: {
    readonly statement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle?: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const proofRecordDigest = input.ballotProof.ballotProofRecordDigest;
    const componentProofBundleDigest =
        input.componentProofBundle?.componentProofBundleDigest;

    if (
        input.ballotProof.componentProofBundleDigest !== undefined &&
        input.componentProofBundle === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record references a component proof bundle that was not supplied.',
                proofRecordDigest,
            ),
        );

        return refusedObjects;
    }
    if (
        input.componentProofBundle !== undefined &&
        input.ballotProof.componentProofBundleDigest === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Supplied component proof bundle is not bound by the ballot proof record.',
                proofRecordDigest,
            ),
        );
    }
    if (input.componentProofBundle === undefined) {
        return refusedObjects;
    }
    refusedObjects.push(
        ...collectBallotProofComponentProofInputRefusals({
            ballotProof: input.ballotProof,
            componentProofBundle: input.componentProofBundle,
            componentProofInputs: input.componentProofInputs,
        }),
    );

    const proofBundlePayload = omitProperty(
        input.componentProofBundle,
        'componentProofBundleDigest',
    );
    const expectedProofBundleDigest =
        deriveBallotProofComponentProofBundleDigest(proofBundlePayload);
    const requiredComponentIdsMatch =
        input.componentProofBundle.requiredComponentIds.length ===
            requiredBallotProofComponentIds.length &&
        input.componentProofBundle.requiredComponentIds.every(
            (componentId, componentIndex) =>
                componentId === requiredBallotProofComponentIds[componentIndex],
        );

    if (
        input.componentProofBundle.objectType !==
            'BallotProofComponentProofBundle' ||
        input.componentProofBundle.objectVersion !== 1 ||
        input.componentProofBundle.bundleCoverage !==
            'full-encoded-score-ballot-relation' ||
        !protocolDigestPattern.test(
            input.componentProofBundle.componentProofBundleDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.componentBundleStatementDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.backendStatementDigest,
        ) ||
        !protocolDigestPattern.test(
            input.componentProofBundle.relationStatementDigest,
        ) ||
        (input.componentProofBundle.ballotProofStatementDigest !== undefined &&
            !protocolDigestPattern.test(
                input.componentProofBundle.ballotProofStatementDigest,
            )) ||
        !requiredComponentIdsMatch
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle has an invalid canonical shape.',
                proofRecordDigest,
            ),
        );
    }
    if (componentProofBundleDigest !== expectedProofBundleDigest) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle digest does not match its canonical payload.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.ballotProof.componentProofBundleDigest !==
        componentProofBundleDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof record is not bound to the supplied component proof bundle.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProofBundle.componentBundleStatementDigest !==
            input.ballotProof.componentBundleStatementDigest ||
        input.componentProofBundle.backendStatementDigest !==
            input.ballotProof.backendStatementDigest ||
        input.componentProofBundle.relationStatementDigest !==
            input.ballotProof.relationStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied proof statement roots.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProofBundle.ballotProofStatementDigest !== undefined &&
        input.componentProofBundle.ballotProofStatementDigest !==
            input.statement.ballotProofStatementDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle is not bound to the supplied ballot proof statement.',
                proofRecordDigest,
            ),
        );
    }
    if (
        input.componentProofBundle.componentProofs.length !==
        requiredBallotProofComponentIds.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot proof component proof bundle must contain exactly the required component proofs.',
                proofRecordDigest,
            ),
        );
    }

    const seenComponentIds = new Set<string>();
    for (
        let componentIndex = 0;
        componentIndex < requiredBallotProofComponentIds.length;
        componentIndex += 1
    ) {
        const expectedComponentId =
            requiredBallotProofComponentIds[componentIndex];
        const componentProofPolicy =
            ballotProofComponentProofPolicyById[expectedComponentId];
        const componentProof =
            input.componentProofBundle.componentProofs[componentIndex];
        if (componentProof === undefined) {
            continue;
        }
        if (seenComponentIds.has(componentProof.componentId)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot proof component proof bundle contains a duplicate component proof.',
                    proofRecordDigest,
                ),
            );
        }
        seenComponentIds.add(componentProof.componentId);

        const componentProofPayload = omitProperty(
            componentProof,
            'componentProofRecordDigest',
        );
        const expectedComponentProofDigest =
            deriveBallotProofComponentProofRecordDigest(componentProofPayload);
        const proofSizeBytesIsValid =
            Number.isSafeInteger(componentProof.proofSizeBytes) &&
            (componentProofPolicy.proofBytesMustBeEmpty
                ? componentProof.proofSizeBytes === 0
                : componentProof.proofSizeBytes > 0);

        if (
            componentProof.objectType !== 'BallotProofComponentProofRecord' ||
            componentProof.objectVersion !== 1 ||
            componentProof.componentId !== expectedComponentId ||
            componentProof.proofBackend !== 'LaZerStyleLocalLatticeRelation' ||
            !protocolDigestPattern.test(
                componentProof.componentProofRecordDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.componentStatementDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.backendStatementDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.relationStatementDigest,
            ) ||
            !protocolDigestPattern.test(componentProof.proofRoot) ||
            !protocolDigestPattern.test(componentProof.proofBytesDigest) ||
            !protocolDigestPattern.test(
                componentProof.proofEncodingProfileDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.proofParameterSetDigest,
            ) ||
            !protocolDigestPattern.test(
                componentProof.publicRandomnessDigest,
            ) ||
            (componentProof.componentProofStatementDigest !== undefined &&
                !protocolDigestPattern.test(
                    componentProof.componentProofStatementDigest,
                )) ||
            (componentProof.ballotProofStatementDigest !== undefined &&
                !protocolDigestPattern.test(
                    componentProof.ballotProofStatementDigest,
                )) ||
            !proofSizeBytesIsValid
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} has an invalid canonical shape.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.componentProofRecordDigest !==
            expectedComponentProofDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof digest for ${expectedComponentId} does not match its canonical payload.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.backendStatementDigest !==
                input.componentProofBundle.backendStatementDigest ||
            componentProof.relationStatementDigest !==
                input.componentProofBundle.relationStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied relation and backend statement.`,
                    proofRecordDigest,
                ),
            );
        }
        if (
            componentProof.ballotProofStatementDigest !== undefined &&
            componentProof.ballotProofStatementDigest !==
                input.statement.ballotProofStatementDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `Ballot proof component proof for ${expectedComponentId} is not bound to the supplied ballot proof statement.`,
                    proofRecordDigest,
                ),
            );
        }
    }

    return refusedObjects;
};

const collectReceiverPayloadStructuralRefusals = (
    payload: ReceiverPayload,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const payloadWithoutDigest = omitProperty(payload, 'receiverPayloadDigest');
    const payloadWithoutRoots = omitProperty(
        payloadWithoutDigest,
        'receiverPayloadCiphertextRoot',
    );
    const expectedCiphertextRoot = deriveReceiverPayloadCiphertextRoot({
        ceremonyId: payload.ceremonyId,
        ciphertextBodyDigest: payload.ciphertextBodyDigest,
        manifestDigest: payload.manifestDigest,
        payloadContextDigest: payload.payloadContextDigest,
        receiverEncryptionProfileDigest:
            payload.receiverEncryptionProfileDigest,
        receiverIdentity: payload.receiverIdentity,
        receiverPublicKeyDigest: payload.receiverPublicKeyDigest,
        receiverRosterPosition: payload.receiverRosterPosition,
    });
    const expectedPayloadDigest = deriveReceiverPayloadDigest({
        ...payloadWithoutRoots,
        receiverPayloadCiphertextRoot: payload.receiverPayloadCiphertextRoot,
    });
    const forbiddenWitnessFields = [
        'receiverShareVector',
        'shareCommitmentOpening',
        'receiverEncryptionRandomness',
        'receiverEncryptionNoise',
        'proofWitness',
    ];

    if (
        payload.objectType !== 'ReceiverPayload' ||
        payload.objectVersion !== 1 ||
        payload.receiverPayloadCiphertextRoot !== expectedCiphertextRoot ||
        payload.receiverPayloadDigest !== expectedPayloadDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload shell digest or shape is invalid.',
                payload.receiverPayloadDigest,
            ),
        );
    }
    for (const forbiddenField of forbiddenWitnessFields) {
        if (hasOwnProperty(payload, forbiddenField)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell must not expose witness material.',
                    payload.receiverPayloadDigest,
                ),
            );
            break;
        }
    }

    return refusedObjects;
};

const collectShareCommitmentStructuralRefusals = (
    shareCommitment: ShareCommitment,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const shareCommitmentPayload = omitProperty(
        shareCommitment,
        'shareCommitmentDigest',
    );
    const expectedShareCommitmentDigest = deriveShareCommitmentDigest(
        shareCommitmentPayload,
    );

    if (
        shareCommitment.objectType !== 'ShareCommitment' ||
        shareCommitment.objectVersion !== 1 ||
        !Number.isSafeInteger(shareCommitment.shareVectorWidth) ||
        shareCommitment.shareVectorWidth <= 0 ||
        shareCommitment.shareCommitmentDigest !== expectedShareCommitmentDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment shell digest or shape is invalid.',
                shareCommitment.shareCommitmentDigest,
            ),
        );
    }
    if (shareCommitment.commitmentPolynomialVector !== undefined) {
        const commitmentPolynomialVector =
            shareCommitment.commitmentPolynomialVector;
        const vectorShapeIsValid =
            commitmentPolynomialVector.length === shareCommitmentModuleRank &&
            commitmentPolynomialVector.every(
                (commitmentPolynomial) =>
                    commitmentPolynomial.length ===
                        shareCommitmentModuleDegree &&
                    commitmentPolynomial.every((coefficient) => {
                        if (!/^(?:0|[1-9][0-9]*)$/u.test(coefficient)) {
                            return false;
                        }

                        return BigInt(coefficient) < shareCommitmentModulus;
                    }),
            );
        const expectedCommitmentBodyDigest = deriveProtocolDigest(
            'ShareCommitmentDigest',
            {
                commitmentPolynomialVector,
                profileDigest: shareCommitment.shareCommitmentProfileDigest,
            },
        );

        if (
            !vectorShapeIsValid ||
            shareCommitment.commitmentBodyDigest !==
                expectedCommitmentBodyDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment polynomial vector is malformed or not bound to the commitment body digest.',
                    shareCommitment.shareCommitmentDigest,
                ),
            );
        }
    }
    if (
        hasOwnProperty(shareCommitment, 'openingRandomness') ||
        hasOwnProperty(shareCommitment, 'receiverShareVector') ||
        hasOwnProperty(shareCommitment, 'proofWitness')
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment shell must not expose witness material.',
                shareCommitment.shareCommitmentDigest,
            ),
        );
    }

    return refusedObjects;
};

const collectClaimBearingPackageStructuralRefusals = (
    ballotPackage: ClaimBearingBallotPackageVerificationShell,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectBallotProofStructuralRefusals(
            ballotPackage.ballotProofStatement,
            ballotPackage.ballotProof,
            ballotPackage.proofBytesHex,
        ),
        ...collectBallotProofComponentProofBundleRefusals({
            ballotProof: ballotPackage.ballotProof,
            componentProofBundle: ballotPackage.componentProofBundle,
            componentProofInputs: ballotPackage.componentProofInputs,
            statement: ballotPackage.ballotProofStatement,
        }),
    ];
    const statement = ballotPackage.ballotProofStatement;
    const statementReceiverKeyReferences = new Map(
        statement.receiverPublicKeys.map((receiverKeyReference) => [
            createReceiverReferenceKey(receiverKeyReference),
            receiverKeyReference,
        ]),
    );
    const statementPayloadReferences = new Map(
        statement.receiverPayloads.map((payloadReference) => [
            createReceiverReferenceKey(payloadReference),
            payloadReference,
        ]),
    );
    const statementCommitmentReferences = new Map(
        statement.shareCommitments.map((commitmentReference) => [
            createReceiverReferenceKey(commitmentReference),
            commitmentReference,
        ]),
    );

    if (
        ballotPackage.objectType !== 'BallotPackage' ||
        ballotPackage.objectVersion !== 1 ||
        ballotPackage.ballotPackageDigest !== statement.ballotPackageDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package shell digest or shape is invalid.',
                ballotPackage.ballotPackageDigest,
            ),
        );
    }
    if (
        ballotPackage.componentProofBundle !== undefined &&
        ballotPackage.proofBytesHex === undefined
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package verification requires the public ballot proof bytes when a component proof bundle is supplied.',
                ballotPackage.ballotPackageDigest,
            ),
        );
    }
    if (
        ballotPackage.receiverPayloads.length !==
        statement.receiverPayloads.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package must include every receiver payload referenced by the statement.',
                ballotPackage.ballotPackageDigest,
            ),
        );
    }
    if (
        ballotPackage.shareCommitments.length !==
        statement.shareCommitments.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Claim-bearing ballot package must include every share commitment referenced by the statement.',
                ballotPackage.ballotPackageDigest,
            ),
        );
    }
    for (const receiverPayload of ballotPackage.receiverPayloads) {
        refusedObjects.push(
            ...collectReceiverPayloadStructuralRefusals(receiverPayload),
        );
        const receiverReferenceKey =
            createReceiverReferenceKey(receiverPayload);
        const payloadReference =
            statementPayloadReferences.get(receiverReferenceKey);
        const receiverKeyReference =
            statementReceiverKeyReferences.get(receiverReferenceKey);
        if (
            payloadReference?.receiverPayloadDigest !==
                receiverPayload.receiverPayloadDigest ||
            payloadReference.receiverPayloadCiphertextRoot !==
                receiverPayload.receiverPayloadCiphertextRoot
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the ballot proof statement reference.',
                    receiverPayload.receiverPayloadDigest,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverPublicKeyDigest !==
                receiverPayload.receiverPublicKeyDigest ||
            receiverPayload.ceremonyId !== statement.ceremonyId ||
            receiverPayload.manifestDigest !== statement.manifestDigest ||
            receiverPayload.rosterDigest !== statement.rosterDigest ||
            receiverPayload.pollSpecDigest !== statement.pollSpecDigest ||
            receiverPayload.voterIdentityDigest !==
                statement.voterIdentityDigest ||
            receiverPayload.receiverEncryptionProfileDigest !==
                statement.receiverEncryptionProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Receiver payload shell is not bound to the statement context or receiver key.',
                    receiverPayload.receiverPayloadDigest,
                ),
            );
        }
    }
    for (const shareCommitment of ballotPackage.shareCommitments) {
        refusedObjects.push(
            ...collectShareCommitmentStructuralRefusals(shareCommitment),
        );
        const receiverReferenceKey =
            createReceiverReferenceKey(shareCommitment);
        const commitmentReference =
            statementCommitmentReferences.get(receiverReferenceKey);
        const receiverKeyReference =
            statementReceiverKeyReferences.get(receiverReferenceKey);
        if (
            commitmentReference?.shareCommitmentDigest !==
            shareCommitment.shareCommitmentDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the ballot proof statement reference.',
                    shareCommitment.shareCommitmentDigest,
                ),
            );
        }
        if (
            receiverKeyReference?.receiverIdentity !==
                shareCommitment.receiverIdentity ||
            receiverKeyReference?.receiverRosterPosition !==
                shareCommitment.receiverRosterPosition ||
            shareCommitment.ceremonyId !== statement.ceremonyId ||
            shareCommitment.manifestDigest !== statement.manifestDigest ||
            shareCommitment.rosterDigest !== statement.rosterDigest ||
            shareCommitment.shareVectorWidth !== statement.shareVectorWidth ||
            shareCommitment.shareCommitmentProfileDigest !==
                statement.shareCommitmentProfileDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Share commitment shell is not bound to the statement context or receiver set.',
                    shareCommitment.shareCommitmentDigest,
                ),
            );
        }
    }

    return refusedObjects;
};

export const verifyReceiverKeyProof = (input: {
    readonly receiverKeyProof: ReceiverKeyProof;
    readonly proofBytesHex?: string;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectReceiverKeyProofStructuralRefusals(
        input.receiverKeyProof,
        input.proofBytesHex,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }

    return createUnavailableProofBackendVerification(
        'verifyReceiverKeyProof',
        input.receiverKeyProof.receiverKeyProofRoot,
    );
};

export const verifyBallotProof = (input: {
    readonly statement: BallotProofStatement;
    readonly ballotProof: BallotProofRecord;
    readonly componentProofBundle?: BallotProofComponentProofBundle;
    readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
    readonly proofBytesHex?: string;
}): BallotPrivacyVerification => {
    const structuralRefusals = [
        ...collectBallotProofStructuralRefusals(
            input.statement,
            input.ballotProof,
            input.proofBytesHex,
        ),
        ...collectBallotProofComponentProofBundleRefusals({
            ballotProof: input.ballotProof,
            componentProofBundle: input.componentProofBundle,
            componentProofInputs: input.componentProofInputs,
            statement: input.statement,
        }),
    ];
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }
    if (input.componentProofBundle !== undefined) {
        return createUnavailableProofBackendVerification(
            'verifyBallotProof',
            input.ballotProof.ballotProofRecordDigest,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyBallotProof',
        input.ballotProof.ballotProofRecordDigest,
    );
};

export const verifyClaimBearingBallotPackage = (input: {
    readonly ballotPackage: ClaimBearingBallotPackageVerificationShell;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectClaimBearingPackageStructuralRefusals(
        input.ballotPackage,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }
    if (input.ballotPackage.componentProofBundle !== undefined) {
        return createUnavailableProofBackendVerification(
            'verifyClaimBearingBallotPackage',
            input.ballotPackage.ballotPackageDigest,
        );
    }

    return createUnavailableProofBackendVerification(
        'verifyClaimBearingBallotPackage',
        input.ballotPackage.ballotPackageDigest,
    );
};
