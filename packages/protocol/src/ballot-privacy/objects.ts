import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyProofBackendStatus,
    BallotPrivacyVerification,
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

const unavailableProofBackendMessage =
    'Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.';
const protocolDigestPattern = /^[a-f0-9]{128}$/u;
const proofBytesHexPattern = /^(?:[a-f0-9]{2})+$/u;

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

export const deriveProofBytesDigest = (input: {
    readonly proofBytesHex: string;
}): ProtocolDigest => {
    if (!proofBytesHexPattern.test(input.proofBytesHex)) {
        throw new RangeError(
            'Proof bytes must be non-empty lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolDigest('ProofBytesDigest', {
        objectType: 'ProofBytes',
        objectVersion: 1,
        proofBytesHex: input.proofBytesHex,
        proofSizeBytes: input.proofBytesHex.length / 2,
    });
};

export const deriveReceiverKeyProofEncodingProfileDigest = (input: {
    readonly proofEncoding: unknown;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        proofEncoding: input.proofEncoding,
        purpose: 'receiver-key-linear-proof-encoding-profile-v1',
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
    ballotPackage: ClaimBearingBallotPackage,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectBallotProofStructuralRefusals(
            ballotPackage.ballotProofStatement,
            ballotPackage.ballotProof,
        ),
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
    readonly proofBytesHex?: string;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectBallotProofStructuralRefusals(
        input.statement,
        input.ballotProof,
        input.proofBytesHex,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }

    return createUnavailableProofBackendVerification(
        'verifyBallotProof',
        input.ballotProof.ballotProofRecordDigest,
    );
};

export const verifyClaimBearingBallotPackage = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
}): BallotPrivacyVerification => {
    const structuralRefusals = collectClaimBearingPackageStructuralRefusals(
        input.ballotPackage,
    );
    if (structuralRefusals.length > 0) {
        return createBallotPrivacyStructuralRejection(structuralRefusals);
    }

    return createUnavailableProofBackendVerification(
        'verifyClaimBearingBallotPackage',
        input.ballotPackage.ballotPackageDigest,
    );
};
