import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BallotPrivacyProofBackendStatus,
    BallotPrivacyRosterProfileEvidence,
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    BallotProofRecord,
    BallotProofStatement,
    ClaimBearingBallotPackage,
    ProtocolHash,
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
    'receiverPublicKeyHash'
>;

type ReceiverKeyProofPayload = Omit<ReceiverKeyProof, 'receiverKeyProofRoot'>;

type ReceiverKeyProofRootEvidencePayload = Omit<
    ReceiverKeyProofRootEvidence,
    'receiverKeyProofRootEvidenceHash'
>;

type ReceiverPayloadCiphertextPayload = Pick<
    ReceiverPayload,
    | 'ceremonyId'
    | 'manifestHash'
    | 'payloadContextHash'
    | 'receiverEncryptionProfileHash'
    | 'receiverIdentity'
    | 'receiverPublicKeyHash'
    | 'receiverRosterPosition'
    | 'ciphertextBodyHash'
>;

type ReceiverPayloadPayload = Omit<ReceiverPayload, 'receiverPayloadHash'>;

type ShareCommitmentPayload = Omit<ShareCommitment, 'shareCommitmentHash'>;

type BallotProofStatementPayload = Omit<
    BallotProofStatement,
    'ballotProofStatementHash'
>;

type BallotProofRecordPayload = Omit<
    BallotProofRecord,
    'ballotProofRecordHash'
>;

type BallotPrivacyRosterProfileEvidencePayload = Omit<
    BallotPrivacyRosterProfileEvidence,
    'rosterProfileEvidenceHash'
>;

type ScopedRelationBearingBallotPackageHashPayload = {
    readonly objectType: 'ClaimBearingBallotPackage';
    readonly objectVersion: 1;
    readonly ballotProofStatement: Omit<
        BallotProofStatementPayload,
        'ballotPackageHash'
    >;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
};

type BallotProofComponentProofRecordPayload = Omit<
    BallotProofComponentProofRecord,
    'componentProofRecordHash'
>;

type BallotProofComponentProofBundlePayload = Omit<
    BallotProofComponentProofBundle,
    'componentProofBundleHash'
>;

type ReceiverEncryptionPublicKeyInput = Omit<
    ReceiverEncryptionPublicKey,
    'objectType' | 'objectVersion' | 'receiverPublicKeyHash'
>;

type ReceiverKeyProofInput = Omit<
    ReceiverKeyProof,
    'objectType' | 'objectVersion' | 'receiverKeyProofRoot'
>;

type ReceiverKeyProofRootEvidenceInput = Omit<
    ReceiverKeyProofRootEvidence,
    'objectType' | 'objectVersion' | 'receiverKeyProofRootEvidenceHash'
>;

type ReceiverPayloadInput = Omit<
    ReceiverPayload,
    | 'objectType'
    | 'objectVersion'
    | 'receiverPayloadCiphertextRoot'
    | 'receiverPayloadHash'
>;

type ShareCommitmentInput = Omit<
    ShareCommitment,
    'objectType' | 'objectVersion' | 'shareCommitmentHash'
>;

export type BallotProofComponentProofVerificationInput = {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementHash: ProtocolHash;
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
    readonly statementHash: ProtocolHash;
};

type UnknownObject = Readonly<Record<string, unknown>>;

type ScopedRelationBearingBallotPackageVerificationShell =
    ClaimBearingBallotPackage & {
        readonly componentProofInputs?: readonly BallotProofComponentProofVerificationInput[];
        readonly proofBytesHex?: string;
    };

const unavailableProofBackendMessage =
    'The pure TypeScript protocol shell does not verify ballot privacy proof bytes or accept scoped relation package claims. Use the packaged Rust/WASM verifier for receiver-key proof, ballot proof-record, and proof-byte-bearing scoped relation package verification.';

const protocolHashPattern = /^[a-f0-9]{128}$/u;

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
    | 'ballotProofStatementHash'
    | 'challengeDomainHash'
    | 'shareVectorWidth'
> & {
    readonly challengeDomainLabel?: string;
};

const deriveReceiverEncryptionPublicKeyHash = (
    publicKey: ReceiverEncryptionPublicKeyPayload,
): ProtocolHash => deriveProtocolHash('PublicKeyHash', publicKey);

const deriveReceiverKeyProofRoot = (
    receiverKeyProof: ReceiverKeyProofPayload,
): ProtocolHash => deriveProtocolHash('ReceiverKeyProofRoot', receiverKeyProof);

const deriveReceiverKeyProofRootEvidenceHash = (
    receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidencePayload,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: receiverKeyProofRootEvidence,
        purpose: 'receiver-key-proof-root-evidence-v1',
    });

const deriveReceiverPayloadCiphertextRoot = (
    receiverPayload: ReceiverPayloadCiphertextPayload,
): ProtocolHash =>
    deriveProtocolHash('ReceiverPayloadCiphertextRoot', receiverPayload);

const deriveReceiverPayloadHash = (
    receiverPayload: ReceiverPayloadPayload,
): ProtocolHash => deriveProtocolHash('ReceiverPayloadHash', receiverPayload);

const deriveShareCommitmentHash = (
    shareCommitment: ShareCommitmentPayload,
): ProtocolHash => deriveProtocolHash('ShareCommitmentHash', shareCommitment);

const deriveBallotProofStatementHash = (
    statement: BallotProofStatementPayload,
): ProtocolHash => deriveProtocolHash('BallotProofStatementHash', statement);

const deriveBallotProofRecordHash = (
    proofRecord: BallotProofRecordPayload,
): ProtocolHash => deriveProtocolHash('BallotProofRecordHash', proofRecord);

const deriveBallotPrivacyRosterProfileEvidenceHash = (
    evidence: BallotPrivacyRosterProfileEvidencePayload,
): ProtocolHash =>
    deriveProtocolHash('BallotPrivacyRosterProfileEvidenceHash', evidence);

const deriveBallotProofComponentProofRecordHash = (
    proofRecord: BallotProofComponentProofRecordPayload,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: proofRecord,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveBallotProofComponentProofBundleHash = (
    proofBundle: BallotProofComponentProofBundlePayload,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: proofBundle,
        purpose: 'ballot-proof-component-proof-bundle-v1',
    });

export const deriveProofBytesHash = (input: {
    readonly allowEmpty?: boolean;
    readonly proofBytesHex: string;
}): ProtocolHash => {
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

    return deriveProtocolHash('ProofBytesHash', {
        objectType: 'ProofBytes',
        objectVersion: 1,
        proofBytesHex: input.proofBytesHex,
        proofSizeBytes: input.proofBytesHex.length / 2,
    });
};

export const deriveBallotProofComponentProofRoot = (input: {
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementHash: ProtocolHash;
    readonly componentStatementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly proofStatementFormat: BallotProofComponentProofVerificationInput['proofStatementFormat'];
    readonly publicRandomnessHash: ProtocolHash;
    readonly statementHash: ProtocolHash;
}): ProtocolHash => {
    const payload: Record<string, unknown> = {
        componentId: input.componentId,
        componentStatementHash: input.componentStatementHash,
        proofBytesHash: input.proofBytesHash,
        proofEncodingProfileHash: input.proofEncodingProfileHash,
        proofParameterSetHash: input.proofParameterSetHash,
        proofStatementFormat: input.proofStatementFormat,
        publicRandomnessHash: input.publicRandomnessHash,
        purpose: 'ballot-proof-component-proof-root-v1',
        statementHash: input.statementHash,
    };
    payload.componentProofStatementHash = input.componentProofStatementHash;

    return deriveProtocolHash('ChallengeDomainHash', payload);
};

export const deriveReceiverKeyProofEncodingProfileHash = (input: {
    readonly proofEncoding: unknown;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        proofEncoding: input.proofEncoding,
        purpose: 'receiver-key-linear-proof-encoding-profile-v1',
    });

export const deriveReceiverKeyProofParameterSetHash = (input: {
    readonly parameterSet: unknown;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        parameterSet: input.parameterSet,
        purpose: 'receiver-key-linear-proof-parameter-set-v1',
    });

export const deriveReceiverKeyProofPublicRandomnessHash = (input: {
    readonly publicRandomnessHex: string;
}): ProtocolHash => {
    if (!/^[a-f0-9]{64}$/u.test(input.publicRandomnessHex)) {
        throw new RangeError(
            'Receiver-key proof public randomness must be 32 lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolHash('ChallengeDomainHash', {
        publicRandomnessHex: input.publicRandomnessHex,
        purpose: 'receiver-key-linear-proof-public-randomness-v1',
    });
};

export const deriveBallotProofEncodingProfileHash = (input: {
    readonly proofEncoding: unknown;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        proofEncoding: input.proofEncoding,
        purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
    });

export const deriveBallotProofParameterSetHash = (input: {
    readonly parameterSet: unknown;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        parameterSet: input.parameterSet,
        purpose: 'ballot-proof-linear-proof-parameter-set-v1',
    });

export const deriveBallotProofPublicRandomnessHash = (input: {
    readonly publicRandomnessHex: string;
}): ProtocolHash => {
    if (!/^[a-f0-9]{64}$/u.test(input.publicRandomnessHex)) {
        throw new RangeError(
            'Ballot proof public randomness must be 32 lowercase hexadecimal bytes.',
        );
    }

    return deriveProtocolHash('ChallengeDomainHash', {
        publicRandomnessHex: input.publicRandomnessHex,
        purpose: 'ballot-proof-linear-proof-public-randomness-v1',
    });
};

const deriveBallotProofChallengeHash = (input: {
    readonly statement: BallotProofStatement;
    readonly backendStatementHash?: ProtocolHash;
    readonly componentBundleStatementHash?: ProtocolHash;
    readonly componentProofBundleHash?: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
    readonly linearStatementHash?: ProtocolHash;
    readonly statementMatrixHash?: ProtocolHash;
    readonly targetVectorHash?: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash?: ProtocolHash;
    readonly proofParameterSetHash?: ProtocolHash;
    readonly publicRandomnessHash?: ProtocolHash;
}): ProtocolHash => {
    const challengePayload: Record<string, unknown> = {
        ballotProofStatementHash: input.statement.ballotProofStatementHash,
        challengeDomainHash: input.statement.challengeDomainHash,
        proofBytesHash: input.proofBytesHash,
        proofRoot: input.proofRoot,
        relationStatementHash: input.relationStatementHash,
    };

    for (const [fieldName, hashValue] of Object.entries({
        backendStatementHash: input.backendStatementHash,
        componentBundleStatementHash: input.componentBundleStatementHash,
        componentProofBundleHash: input.componentProofBundleHash,
        linearStatementHash: input.linearStatementHash,
        proofEncodingProfileHash: input.proofEncodingProfileHash,
        proofParameterSetHash: input.proofParameterSetHash,
        publicRandomnessHash: input.publicRandomnessHash,
        statementMatrixHash: input.statementMatrixHash,
        targetVectorHash: input.targetVectorHash,
    })) {
        if (hashValue !== undefined) {
            challengePayload[fieldName] = hashValue;
        }
    }

    return deriveProtocolHash('ChallengeDomainHash', challengePayload);
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

const scopedRelationBearingBallotPackageHashPayload = (input: {
    readonly ballotProofStatement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
}): ScopedRelationBearingBallotPackageHashPayload => ({
    objectType: 'ClaimBearingBallotPackage',
    objectVersion: 1,
    ballotProofStatement: omitProperty(
        omitProperty(input.ballotProofStatement, 'ballotProofStatementHash'),
        'ballotPackageHash',
    ),
    receiverKeyProofRootEvidence: input.receiverKeyProofRootEvidence,
    receiverPayloads: input.receiverPayloads,
    shareCommitments: input.shareCommitments,
});

export const deriveClaimBearingBallotPackageHash = (input: {
    readonly ballotProofStatement: BallotProofStatement;
    readonly receiverKeyProofRootEvidence: ReceiverKeyProofRootEvidence;
    readonly receiverPayloads: readonly ReceiverPayload[];
    readonly shareCommitments: readonly ShareCommitment[];
}): ProtocolHash =>
    deriveProtocolHash(
        'BallotPackageHash',
        scopedRelationBearingBallotPackageHashPayload(input),
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
    readonly objectHash: ProtocolHash;
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
                    input.objectHash,
                ),
            );
            continue;
        }
        if (seenReceiverReferences.has(receiverReferenceKey)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    `${input.label} contains a duplicate receiver reference.`,
                    input.objectHash,
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
        receiverPublicKeyHash:
            deriveReceiverEncryptionPublicKeyHash(publicKeyPayload),
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
        receiverKeyProofRootEvidenceHash:
            deriveReceiverKeyProofRootEvidenceHash(evidencePayload),
    };
};

export {
    unavailableProofBackendMessage,
    protocolHashPattern,
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
    deriveReceiverKeyProofRootEvidenceHash,
    deriveReceiverPayloadCiphertextRoot,
    deriveReceiverPayloadHash,
    deriveShareCommitmentHash,
    deriveBallotProofStatementHash,
    deriveBallotProofRecordHash,
    deriveBallotPrivacyRosterProfileEvidenceHash,
    deriveBallotProofComponentProofRecordHash,
    deriveBallotProofComponentProofBundleHash,
    deriveBallotProofChallengeHash,
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
