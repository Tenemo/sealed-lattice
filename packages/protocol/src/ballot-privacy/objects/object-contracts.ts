import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyProofBackendStatus,
    BallotPrivacyRosterProfileEvidence,
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    BallotProofRecord,
    BallotProofStatement,
    ClaimBearingBallotPackage,
    ProtocolDigest,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
    ReceiverKeyProofRootEvidence,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import {
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
} from '../protocol-parameters.js';

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyDigest'
>;

type ReceiverKeyProofPayload = Omit<ReceiverKeyProof, 'receiverKeyProofRoot'>;

type ReceiverKeyProofRootEvidencePayload = Omit<
    ReceiverKeyProofRootEvidence,
    'receiverKeyProofRootEvidenceDigest'
>;

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

type BallotPrivacyRosterProfileEvidencePayload = Omit<
    BallotPrivacyRosterProfileEvidence,
    'rosterProfileEvidenceDigest'
>;

type ScopedRelationBearingBallotPackageDigestPayload = {
    readonly objectType: 'ClaimBearingBallotPackage';
    readonly objectVersion: 1;
    readonly ballotProofStatement: Omit<
        BallotProofStatementPayload,
        'ballotPackageDigest'
    >;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
};

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

type ReceiverKeyProofRootEvidenceInput = Omit<
    ReceiverKeyProofRootEvidence,
    'objectType' | 'objectVersion' | 'receiverKeyProofRootEvidenceDigest'
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
    readonly componentProofStatementDigest: ProtocolDigest;
    readonly proofBytesHex: string;
    readonly proofEncoding: unknown;
    readonly proofParameterSet: unknown;
    readonly proofStatement?: unknown;
    readonly proofStatementFormat:
        | 'dense-polynomial-matrix-linear-proof-v1'
        | 'sparse-polynomial-matrix-linear-proof-v1'
        | 'structured-module-sis-share-commitment-v1'
        | 'structured-module-lwe-linear-proof-v1'
        | 'public-zero-witness-binding-check-v1';
    readonly publicRandomnessHex: string;
    readonly statementDigest: ProtocolDigest;
};

type UnknownObject = Readonly<Record<string, unknown>>;

type ScopedRelationBearingBallotPackageVerificationShell =
    ClaimBearingBallotPackage & {
        readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
        readonly proofBytesHex?: string;
    };

const unavailableProofBackendMessage =
    'The pure TypeScript protocol shell does not verify ballot privacy proof bytes or accept scoped relation package claims. Use the packaged Rust/WASM verifier for receiver-key proof, ballot proof-record, and proof-byte-bearing scoped relation package verification.';

const protocolDigestPattern = /^[a-f0-9]{128}$/u;

const proofBytesHexPattern = /^(?:[a-f0-9]{2})+$/u;

const proofBytesHexAllowEmptyPattern = /^(?:[a-f0-9]{2})*$/u;

const unsignedDecimalStringPattern = /^(?:0|[1-9][0-9]*)$/u;

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
    'structured-module-sis-share-commitment-v1',
    'structured-module-lwe-linear-proof-v1',
    'public-zero-witness-binding-check-v1',
]);

type BallotProofComponentProofBytesAvailability =
    | 'available-for-small-dense-oracle'
    | 'requires-sparse-proof-statement'
    | 'requires-structured-proof-statement'
    | 'public-zero-witness-binding-check';

const componentProofBytesMustBeEmpty = (
    componentId: BallotProofComponentId,
): boolean => componentId === 'receiver-key-binding-component';

const componentProofStatementFormatIsExpected = (
    componentId: BallotProofComponentId,
    proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'],
): boolean => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
            return (
                proofStatementFormat ===
                    'dense-polynomial-matrix-linear-proof-v1' ||
                proofStatementFormat ===
                    'sparse-polynomial-matrix-linear-proof-v1'
            );
        case 'payload-plaintext-field-component':
            return (
                proofStatementFormat ===
                'sparse-polynomial-matrix-linear-proof-v1'
            );
        case 'share-commitment-component':
            return (
                proofStatementFormat ===
                    'sparse-polynomial-matrix-linear-proof-v1' ||
                proofStatementFormat ===
                    'structured-module-sis-share-commitment-v1'
            );
        case 'receiver-encryption-component':
            return (
                proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
            );
        case 'receiver-key-binding-component':
            return (
                proofStatementFormat === 'public-zero-witness-binding-check-v1'
            );
    }
};

const expectedComponentProofStatementFormatLabel = (
    componentId: BallotProofComponentId,
): string => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
            return 'dense-polynomial-matrix-linear-proof-v1 or sparse-polynomial-matrix-linear-proof-v1';
        case 'share-commitment-component':
            return 'sparse-polynomial-matrix-linear-proof-v1 or structured-module-sis-share-commitment-v1';
        case 'payload-plaintext-field-component':
            return 'sparse-polynomial-matrix-linear-proof-v1';
        case 'receiver-encryption-component':
            return 'structured-module-lwe-linear-proof-v1';
        case 'receiver-key-binding-component':
            return 'public-zero-witness-binding-check-v1';
    }
};

const componentProofBytesAvailabilityForStatementFormat = (
    proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'],
): BallotProofComponentProofBytesAvailability => {
    switch (proofStatementFormat) {
        case 'dense-polynomial-matrix-linear-proof-v1':
            return 'available-for-small-dense-oracle';
        case 'sparse-polynomial-matrix-linear-proof-v1':
        case 'structured-module-sis-share-commitment-v1':
            return 'requires-sparse-proof-statement';
        case 'structured-module-lwe-linear-proof-v1':
            return 'requires-structured-proof-statement';
        case 'public-zero-witness-binding-check-v1':
            return 'public-zero-witness-binding-check';
    }
};

const componentProofBytesAvailabilityIsExpected = (
    componentId: BallotProofComponentId,
    proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'],
    proofBytesAvailability: string,
): boolean =>
    componentProofStatementFormatIsExpected(
        componentId,
        proofStatementFormat,
    ) &&
    componentProofBytesAvailabilityForStatementFormat(proofStatementFormat) ===
        proofBytesAvailability;

export const describeBallotPrivacyProofBackend =
    (): BallotPrivacyProofBackendStatus => ({
        backendName: 'linear lattice proof backend',
        backendAvailable: false,
        portableRustWasmPortRequired: true,
        requiredComponents: [],
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

const deriveReceiverKeyProofRootEvidenceDigest = (
    receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidencePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: receiverKeyProofRootEvidence,
        purpose: 'receiver-key-proof-root-evidence-v1',
    });

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

const deriveBallotPrivacyRosterProfileEvidenceDigest = (
    evidence: BallotPrivacyRosterProfileEvidencePayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotPrivacyRosterProfileEvidenceDigest', evidence);

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
    readonly componentProofStatementDigest: ProtocolDigest;
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
    payload.componentProofStatementDigest = input.componentProofStatementDigest;

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

const scopedRelationBearingBallotPackageDigestPayload = (input: {
    readonly ballotProofStatement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
}): ScopedRelationBearingBallotPackageDigestPayload => ({
    objectType: 'ClaimBearingBallotPackage',
    objectVersion: 1,
    ballotProofStatement: omitProperty(
        omitProperty(input.ballotProofStatement, 'ballotProofStatementDigest'),
        'ballotPackageDigest',
    ),
    receiverKeyProofRootEvidence: input.receiverKeyProofRootEvidence,
    receiverPayloads: input.receiverPayloads,
    shareCommitments: input.shareCommitments,
});

export const deriveClaimBearingBallotPackageDigest = (input: {
    readonly ballotProofStatement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
}): ProtocolDigest =>
    deriveProtocolDigest(
        'BallotPackageDigest',
        scopedRelationBearingBallotPackageDigestPayload(input),
    );

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

export const createReceiverKeyProofRootEvidence = (
    input: ReceiverKeyProofRootEvidenceInput,
): ReceiverKeyProofRootEvidence => {
    const evidencePayload: ReceiverKeyProofRootEvidencePayload = {
        objectType: 'ReceiverKeyProofRootEvidence',
        objectVersion: 1,
        ...input,
    };

    return {
        ...evidencePayload,
        receiverKeyProofRootEvidenceDigest:
            deriveReceiverKeyProofRootEvidenceDigest(evidencePayload),
    };
};

export {
    unavailableProofBackendMessage,
    protocolDigestPattern,
    proofBytesHexPattern,
    proofBytesHexAllowEmptyPattern,
    unsignedDecimalStringPattern,
    shareCommitmentModuleRank,
    shareCommitmentModuleDegree,
    shareCommitmentModulus,
    requiredBallotProofComponentIds,
    allowedBallotProofComponentStatementFormats,
    componentProofBytesMustBeEmpty,
    componentProofStatementFormatIsExpected,
    expectedComponentProofStatementFormatLabel,
    componentProofBytesAvailabilityIsExpected,
    deriveReceiverKeyProofRoot,
    deriveReceiverKeyProofRootEvidenceDigest,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadDigest,
    deriveShareCommitmentDigest,
    deriveBallotProofStatementDigest,
    deriveBallotProofRecordDigest,
    deriveBallotPrivacyRosterProfileEvidenceDigest,
    deriveBallotProofComponentProofRecordDigest,
    deriveBallotProofComponentProofBundleDigest,
    deriveBallotProofChallengeDigest,
    hasOwnProperty,
    omitProperty,
    isUnknownObject,
    omitUnknownObjectProperty,
    createReceiverReferenceKey,
    collectReceiverReferenceRefusals,
};
export type {
    ReceiverPayloadPayload,
    ShareCommitmentPayload,
    BallotProofStatementPayload,
    BallotProofRecordPayload,
    ReceiverPayloadInput,
    ShareCommitmentInput,
    UnknownObject,
    ScopedRelationBearingBallotPackageVerificationShell,
    BallotProofStatementInput,
};
