import { canonicalJson, deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from './common-randomness-records.js';
import type {
    GaloisKeyShareBatch,
    PublicEvaluationKeySet,
    RelinearizationKeyShareRounds,
    TransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet,
    TrusteeEvaluationKeyProofSet,
} from './evaluation-key-proof-records.js';
import type {
    EvaluatorKeySchedule,
    RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
import type {
    CollectivePublicKey,
    PublicKeyShareProofSet,
    SetupPackagePublicKeyShareMaterialSet,
    SetupTransportedPublicKeyShareMaterial,
    PublicKeyShareSet,
    PublicKeyShareSuccinctProofSet,
    TransportedPublicKeyShareProofMaterialSet,
} from './public-key-share-records.js';
import {
    createCollectivePublicKey,
    createCollectivePublicKeyFromTransportedPublicKeyShareMaterial,
    publicKeyShareMaterialTransportEncoding,
} from './public-key-share-records.js';
import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
    TransportedSameSecretProofMaterialSet,
} from './same-secret-consistency-records.js';
import {
    createSetupCertificates,
    type SetupCertificateTransportedObjectInput,
    type SetupCertificatesInput,
} from './setup-certificates.js';
import type { SetupPhaseRecord } from './setup-phase-records.js';
import {
    chunklessSetupProofMaterialSetForVerificationInput,
    type VerifiedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from './threshold-share-commitments.js';
import type {
    SetupPackageVssCoefficientCommitmentMaterialSet,
    SetupTransportedVssCoefficientCommitmentMaterial,
    SetupTransportedVssCoefficientCommitmentMaterialLike,
    VerifiedVssCoefficientCommitmentMaterial,
    VssCoefficientCommitmentSet,
} from './vss-coefficient-commitments.js';
import type {
    CollectiveBgvSetupContext,
    VssComplaintSet,
    VssShareAcceptanceSet,
} from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export type SetupPackageCertificateInput = Omit<
    SetupCertificatesInput,
    'vssCoefficientCommitmentMaterial'
>;

type SetupPackageCertificateRecords = Readonly<{
    readonly setupCommitmentSecurityCertificate: JsonRecord;
    readonly setupTransportCertificate: JsonRecord;
    readonly setupProofAccountingCertificate: JsonRecord;
    readonly heSecurityCertificate: JsonRecord;
}>;

export type SetupKeyCorrectnessCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupKeyCorrectnessCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
    }
>;

type SetupKeyCorrectnessCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupKeyCorrectnessCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type ActiveStaticSetupTheoremCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'ActiveStaticSetupTheoremCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
    }
>;

type ActiveStaticSetupTheoremCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'ActiveStaticSetupTheoremCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly transportedVssCoefficientCommitmentMaterial?:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet | JsonRecord;
    readonly thresholdShareCommitments?:
        | ThresholdShareCommitmentSet
        | JsonRecord;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
    readonly transportedSameSecretProofMaterial?:
        | TransportedSameSecretProofMaterialSet
        | JsonRecord;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial:
        | SetupPackagePublicKeyShareMaterialSet
        | JsonRecord;
    readonly transportedPublicKeyShareMaterial?:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
    readonly publicKeyShareSuccinctProofs:
        | PublicKeyShareSuccinctProofSet
        | JsonRecord;
    readonly transportedPublicKeyShareProofMaterial?:
        | TransportedPublicKeyShareProofMaterialSet
        | JsonRecord;
    readonly collectivePublicKey?: never;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial?:
        | TransportedEvaluationKeyShareProofMaterialSet
        | JsonRecord;
    readonly transportedEvaluationKeyShareComponentMaterial?:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | JsonRecord;
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly transportedPublicEvaluationKeyMaterial?:
        | TransportedPublicEvaluationKeyMaterialSet
        | JsonRecord;
    readonly setupCertificateInput?: SetupPackageCertificateInput;
    readonly setupCommitmentSecurityCertificate?: JsonRecord;
    readonly setupTransportCertificate?: JsonRecord;
    readonly setupProofAccountingCertificate?: JsonRecord;
    readonly heSecurityCertificate?: JsonRecord;
}>;

export type SetupPackage = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPackage';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupContext: CollectiveBgvSetupContext;
        readonly qShare: JsonRecord;
        readonly phaseTranscript: readonly SetupPhaseRecord[];
        readonly commonRandomness: SetupCommonRandomness;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly vssCoefficientCommitmentMaterial:
            | SetupPackageVssCoefficientCommitmentMaterialSet
            | JsonRecord;
        readonly privateVssEnvelopeCommitments: JsonRecord;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly vssComplaints?: VssComplaintSet | JsonRecord;
        readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
        readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
        readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
        readonly publicKeyShares: PublicKeyShareSet;
        readonly publicKeyShareProofs: PublicKeyShareProofSet;
        readonly publicKeyShareMaterial:
            | SetupPackagePublicKeyShareMaterialSet
            | JsonRecord;
        readonly publicKeyShareSuccinctProofs:
            | PublicKeyShareSuccinctProofSet
            | JsonRecord;
        readonly collectivePublicKey: CollectivePublicKey | JsonRecord;
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly evaluatorKeySchedule: EvaluatorKeySchedule;
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
        readonly evaluationKeys: PublicEvaluationKeySet;
        readonly setupCommitmentSecurityCertificate: JsonRecord;
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificate: JsonRecord;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificate: JsonRecord;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificate: SetupKeyCorrectnessCertificate;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly activeStaticSetupTheoremCertificate: ActiveStaticSetupTheoremCertificate;
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
        readonly heSecurityCertificate: JsonRecord;
        readonly heSecurityCertificateHash: ProtocolHash;
        readonly setupPackageHash: ProtocolHash;
    }
>;

export type SetupPackageVerificationInputSource = Readonly<{
    readonly setupPackage: SetupPackage;
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterialLike;
    readonly verifiedVssCoefficientCommitmentMaterial?: VerifiedVssCoefficientCommitmentMaterial;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: VerifiedSetupProofMaterialSet;
}>;

export type SetupPackageVerificationInput = SetupPackageVerificationInputSource;

const publicVssMaterialReferenceForVerificationInput = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterialLike
        | undefined,
    verifiedMaterial: VerifiedVssCoefficientCommitmentMaterial | undefined,
): SetupTransportedVssCoefficientCommitmentMaterialLike | undefined => {
    if (transportedMaterial === undefined) {
        return undefined;
    }
    if (
        verifiedMaterial === undefined ||
        !Object.prototype.hasOwnProperty.call(transportedMaterial, 'chunks')
    ) {
        return transportedMaterial;
    }

    const { chunks: omittedChunks, ...transportedMaterialReference } =
        transportedMaterial as SetupTransportedVssCoefficientCommitmentMaterial;
    void omittedChunks;

    return transportedMaterialReference;
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    const transportedVssCoefficientCommitmentMaterial =
        publicVssMaterialReferenceForVerificationInput(
            input.transportedVssCoefficientCommitmentMaterial,
            input.verifiedVssCoefficientCommitmentMaterial,
        );
    const transportedSameSecretProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedSameSecretProofMaterial,
            input.verifiedSetupProofMaterials,
        );
    const transportedPublicKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedPublicKeyShareProofMaterial,
            input.verifiedSetupProofMaterials,
        );
    const transportedEvaluationKeyShareProofMaterial =
        chunklessSetupProofMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareProofMaterial,
            input.verifiedSetupProofMaterials,
        );

    return {
        setupPackage: input.setupPackage,
        ...(transportedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial,
              }),
        ...(input.verifiedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  verifiedVssCoefficientCommitmentMaterial:
                      input.verifiedVssCoefficientCommitmentMaterial,
              }),
        ...(transportedSameSecretProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretProofMaterial:
                      transportedSameSecretProofMaterial,
              }),
        ...(input.transportedPublicKeyShareMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      input.transportedPublicKeyShareMaterial,
              }),
        ...(transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      transportedPublicKeyShareProofMaterial,
              }),
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      transportedEvaluationKeyShareProofMaterial,
              }),
        ...(input.transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      input.transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(input.transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      input.transportedPublicEvaluationKeyMaterial,
              }),
        ...(input.verifiedSetupProofMaterials === undefined
            ? {}
            : {
                  verifiedSetupProofMaterials:
                      input.verifiedSetupProofMaterials,
              }),
    };
};

type SetupPackageInputWithDerivedCollectivePublicKey = Omit<
    SetupPackageInput,
    'collectivePublicKey'
> &
    Readonly<{
        readonly collectivePublicKey: CollectivePublicKey;
    }>;

const setupProfileId = 'CollectiveBgvSetup-v1';
const firstProfileParticipantCount = 10;
const firstProfileSetupCompletionQuorum = 10;
const firstProfileDecryptionThreshold = 4;
const protocolHashPattern = /^[0-9a-f]{128}$/u;
const setupContextTokenPattern = /^[A-Za-z0-9._:/@+-]{1,128}$/u;
const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;
const commonRandomnessContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'setupEpoch',
] as const;
const requiredSetupPhases = [
    ['rosterFreeze', 1],
    ['setupIntent', 2],
    ['commonRandomnessCommit', 3],
    ['commonRandomnessReveal', 4],
    ['vssCoefficientCommitments', 5],
    ['privateVssEnvelopeDelivery', 6],
    ['recipientVssVerification', 7],
    ['vssAcceptanceOrComplaint', 8],
    ['publicKeyShareProofs', 9],
    ['relinearizationRoundOne', 10],
    ['relinearizationRoundTwo', 11],
    ['galoisKeyShareBatches', 12],
    ['trusteeEvaluationKeyProofs', 13],
    ['setupPackageAssembly', 14],
    ['setupPackageVerification', 15],
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertSetupContextToken = (value: string, fieldName: string): void => {
    if (!setupContextTokenPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a bounded setup context token.`,
        );
    }
};

const assertObjectRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertContext = (setupContext: CollectiveBgvSetupContext): void => {
    for (const fieldName of contextFieldNames) {
        assertNonEmptyString(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
    for (const fieldName of ['ceremonyId', 'setupEpoch'] as const) {
        assertSetupContextToken(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
    for (const fieldName of [
        'manifestHash',
        'rosterHash',
        'setupProfileHash',
        'qShareHash',
        'carryAwareVssShareRelationProfileHash',
        'commitmentProfileHash',
    ] as const) {
        assertProtocolHash(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
};

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const assertCommonRandomnessContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => {
    for (const fieldName of commonRandomnessContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const objectTypeAt = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
): string => {
    const objectType = value.objectType;
    if (typeof objectType !== 'string' || objectType.length === 0) {
        throw new TypeError(`${fieldName}.objectType must be non-empty.`);
    }

    return objectType;
};

const assertObjectType = (
    value: unknown,
    fieldName: string,
    expectedObjectType: string,
): void => {
    const objectRecord = assertObjectRecord(value, fieldName);
    const objectType = objectTypeAt(objectRecord, fieldName);
    if (objectType !== expectedObjectType) {
        throw new Error(
            `${fieldName}.objectType must be ${expectedObjectType}.`,
        );
    }
    if (objectRecord.objectVersion !== 1) {
        throw new Error(`${fieldName}.objectVersion must be 1.`);
    }
};

const hashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const hashValue = value[fieldName];
    if (typeof hashValue !== 'string') {
        throw new TypeError(`${objectPath}.${fieldName} must be a string.`);
    }
    assertProtocolHash(hashValue, `${objectPath}.${fieldName}`);

    return hashValue;
};

const optionalHashValue = (
    value: unknown,
    fieldPath: string,
): ProtocolHash | null => {
    if (value === undefined) {
        return null;
    }
    if (typeof value !== 'string') {
        throw new TypeError(`${fieldPath} must be a string when present.`);
    }
    assertProtocolHash(value, fieldPath);

    return value;
};

const optionalTopLevelHashValue = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
): ProtocolHash | null => optionalHashValue(value[fieldName], fieldName);

const optionalNestedHashValue = (
    value: Readonly<Record<string, unknown>>,
    objectFieldName: string,
    hashFieldName: string,
): ProtocolHash | null => {
    const objectValue = value[objectFieldName];
    if (objectValue === undefined) {
        return null;
    }
    const record = assertObjectRecord(
        objectValue,
        `setupPackage.${objectFieldName}`,
    );

    return optionalHashValue(
        record[hashFieldName],
        `setupPackage.${objectFieldName}.${hashFieldName}`,
    );
};

const cloneJsonLike = (value: unknown): unknown => {
    if (Array.isArray(value)) {
        return value.map(cloneJsonLike);
    }
    if (typeof value !== 'object' || value === null) {
        return value;
    }

    return Object.fromEntries(
        Object.entries(value as JsonRecord).map(([fieldName, fieldValue]) => [
            fieldName,
            cloneJsonLike(fieldValue),
        ]),
    );
};

const publicPrivateVssEnvelopeCommitmentReference = (
    envelopeReference: JsonRecord,
): JsonRecord => {
    const {
        encryptedEnvelope,
        encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial,
        transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...publicReference
    } = envelopeReference;
    void encryptedEnvelope;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterial;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return publicReference;
};

const publicPrivateVssEnvelopeCommitmentSet = (
    privateVssEnvelopeCommitments: JsonRecord,
): JsonRecord => {
    const envelopeReferences = privateVssEnvelopeCommitments.envelopeReferences;
    if (!Array.isArray(envelopeReferences)) {
        throw new TypeError(
            'privateVssEnvelopeCommitments.envelopeReferences must be an array.',
        );
    }

    return {
        ...privateVssEnvelopeCommitments,
        envelopeReferences: envelopeReferences.map((envelopeReference) =>
            publicPrivateVssEnvelopeCommitmentReference(
                assertObjectRecord(
                    envelopeReference,
                    'privateVssEnvelopeCommitments.envelopeReferences',
                ),
            ),
        ),
    };
};

export const setupPackageHashInput = (
    setupPackage: Readonly<SetupPackage | JsonRecord>,
): JsonRecord => {
    const hashInput = cloneJsonLike(setupPackage) as JsonRecord;
    delete hashInput.setupPackageHash;
    const privateVssEnvelopeCommitments =
        hashInput.privateVssEnvelopeCommitments;
    if (privateVssEnvelopeCommitments !== undefined) {
        hashInput.privateVssEnvelopeCommitments =
            publicPrivateVssEnvelopeCommitmentSet(
                assertObjectRecord(
                    privateVssEnvelopeCommitments,
                    'privateVssEnvelopeCommitments',
                ),
            );
    }

    return hashInput;
};

const assertPhaseTranscript = (
    setupContext: CollectiveBgvSetupContext,
    phaseTranscript: readonly SetupPhaseRecord[],
): void => {
    if (phaseTranscript.length !== requiredSetupPhases.length) {
        throw new Error(
            'phaseTranscript must contain the complete accepted setup phase order.',
        );
    }
    let previousPhaseRoot: ProtocolHash | null = null;
    for (const [phaseIndex, phaseRecord] of phaseTranscript.entries()) {
        const objectPath = `phaseTranscript.${String(phaseIndex)}`;
        const [expectedPhaseId, expectedPhaseNumber] =
            requiredSetupPhases[phaseIndex];
        if (
            phaseRecord.phaseId !== expectedPhaseId ||
            phaseRecord.phaseNumber !== expectedPhaseNumber
        ) {
            throw new Error(
                `${objectPath} must be ${expectedPhaseId} phase ${String(expectedPhaseNumber)}.`,
            );
        }
        if (phaseRecord.previousPhaseRoot !== previousPhaseRoot) {
            throw new Error(
                `${objectPath}.previousPhaseRoot must match the previous phase root.`,
            );
        }
        assertContextMatches(setupContext, phaseRecord, objectPath);
        previousPhaseRoot = hashField(phaseRecord, 'phaseRoot', objectPath);
    }
};

const assertCommonBindings = (input: SetupPackageInput): void => {
    assertContext(input.setupContext);
    assertObjectType(input.qShare, 'qShare', 'QSharePrimeList');
    if (
        deriveProtocolHash('QSharePrimeListHash', input.qShare) !==
        input.setupContext.qShareHash
    ) {
        throw new Error('qShare must match setupContext.qShareHash.');
    }
    assertPhaseTranscript(input.setupContext, input.phaseTranscript);
    assertObjectType(
        input.commonRandomness,
        'commonRandomness',
        'SetupCommonRandomness',
    );
    assertCommonRandomnessContextMatches(
        input.setupContext,
        input.commonRandomness,
        'commonRandomness',
    );
    hashField(
        input.commonRandomness,
        'commonRandomnessRoot',
        'commonRandomness',
    );
    assertObjectType(
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
        'VssCoefficientCommitmentSet',
    );
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
    );
    hashField(
        input.vssCoefficientCommitments,
        'vssCoefficientCommitmentRoot',
        'vssCoefficientCommitments',
    );
    assertObjectType(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
        'VssCoefficientCommitmentMaterialSet',
    );
    hashField(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterialRoot',
        'vssCoefficientCommitmentMaterial',
    );
    assertObjectType(
        input.privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
        'PrivateVssEnvelopeCommitmentSet',
    );
    hashField(
        input.privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitmentRoot',
        'privateVssEnvelopeCommitments',
    );
    assertObjectType(
        input.vssShareAcceptances,
        'vssShareAcceptances',
        'VssShareAcceptanceSet',
    );
    assertContextMatches(
        input.setupContext,
        input.vssShareAcceptances,
        'vssShareAcceptances',
    );
    hashField(
        input.vssShareAcceptances,
        'vssShareAcceptanceRoot',
        'vssShareAcceptances',
    );
    if (input.vssComplaints !== undefined) {
        assertObjectType(
            input.vssComplaints,
            'vssComplaints',
            'VssComplaintSet',
        );
        hashField(input.vssComplaints, 'vssComplaintRoot', 'vssComplaints');
    }
};

const assertKeyRecordBindings = (input: SetupPackageInput): void => {
    assertObjectType(
        input.sameSecretConsistency,
        'sameSecretConsistency',
        'SameSecretConsistencyStatementSet',
    );
    hashField(
        input.sameSecretConsistency,
        'sameSecretConsistencyRoot',
        'sameSecretConsistency',
    );
    assertObjectType(
        input.sameSecretProofs,
        'sameSecretProofs',
        'SameSecretProofSet',
    );
    hashField(
        input.sameSecretProofs,
        'sameSecretProofSetRoot',
        'sameSecretProofs',
    );
    assertObjectType(
        input.publicKeyShares,
        'publicKeyShares',
        'PublicKeyShareSet',
    );
    hashField(
        input.publicKeyShares,
        'publicKeyShareSetRoot',
        'publicKeyShares',
    );
    assertObjectType(
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
        'PublicKeyShareProofSet',
    );
    hashField(
        input.publicKeyShareProofs,
        'publicKeyShareProofSetRoot',
        'publicKeyShareProofs',
    );
    assertObjectType(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
        'PublicKeyShareMaterialSet',
    );
    hashField(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
    );
    assertObjectType(
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofs',
        'PublicKeyShareSuccinctProofSet',
    );
    hashField(
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofSetRoot',
        'publicKeyShareSuccinctProofs',
    );
    assertObjectType(
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
        'EvaluatorKeySchedule',
    );
    hashField(
        input.evaluatorKeySchedule,
        'evaluatorKeyScheduleRoot',
        'evaluatorKeySchedule',
    );
    assertObjectType(
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
        'RelinearizationKeyShareRounds',
    );
    hashField(
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRoundsRoot',
        'relinearizationKeyShareRounds',
    );
    for (const [batchIndex, batch] of input.galoisKeyShareBatches.entries()) {
        const objectPath = `galoisKeyShareBatches.${String(batchIndex)}`;
        assertObjectType(batch, objectPath, 'GaloisKeyShareBatch');
        hashField(batch, 'galoisKeyShareBatchRoot', objectPath);
    }
    assertObjectType(
        input.trusteeEvaluationKeyProofs,
        'trusteeEvaluationKeyProofs',
        'TrusteeEvaluationKeyProofSet',
    );
    hashField(
        input.trusteeEvaluationKeyProofs,
        'trusteeEvaluationKeyProofSetRoot',
        'trusteeEvaluationKeyProofs',
    );
    if (
        input.trusteeEvaluationKeyProofs.relinearizationKeyShareRoundsRoot !==
        input.relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot
    ) {
        throw new Error(
            'trusteeEvaluationKeyProofs must bind the supplied relinearization share-record container.',
        );
    }
    assertObjectType(
        input.evaluationKeys,
        'evaluationKeys',
        'PublicEvaluationKeySet',
    );
    hashField(input.evaluationKeys, 'evaluationKeySetHash', 'evaluationKeys');
};

const assertCommonRandomnessPublicDerivationsBindPackageInput = (
    input: SetupPackageInput,
): void => {
    const publicMatrixSeedHash = hashField(
        input.commonRandomness,
        'publicMatrixSeedHash',
        'commonRandomness',
    );
    const publicDerivations = assertObjectRecord(
        input.commonRandomness.publicDerivations,
        'commonRandomness.publicDerivations',
    );
    if (
        publicDerivations.objectType !== 'SetupPublicDerivations' ||
        publicDerivations.objectVersion !== 1 ||
        publicDerivations.setupProfileId !== setupProfileId ||
        publicDerivations.publicMatrixSeedHash !== publicMatrixSeedHash ||
        publicDerivations.status !== 'deterministic-public-derivations-bound'
    ) {
        throw new Error(
            'commonRandomness.publicDerivations must match the accepted setup public derivation profile.',
        );
    }

    const crpRoots = assertObjectRecord(
        publicDerivations.crpRoots,
        'commonRandomness.publicDerivations.crpRoots',
    );
    const bgvPublicA = assertObjectRecord(
        publicDerivations.bgvPublicA,
        'commonRandomness.publicDerivations.bgvPublicA',
    );
    const publicKeyShareMaterial = assertObjectRecord(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    if (publicKeyShareMaterial.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            'publicKeyShareMaterial.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash.',
        );
    }
    if (publicKeyShareMaterial.publicKeyCrpRoot !== crpRoots.publicKeyCrpRoot) {
        throw new Error(
            'publicKeyShareMaterial.publicKeyCrpRoot must match commonRandomness public derivations.',
        );
    }
    if (
        publicKeyShareMaterial.publicAPolynomialRoot !==
        bgvPublicA.publicPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShareMaterial.publicAPolynomialRoot must match commonRandomness public derivations.',
        );
    }

    const evaluatorKeySchedule = assertObjectRecord(
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
    );
    if (evaluatorKeySchedule.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            'evaluatorKeySchedule.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash.',
        );
    }
    if (
        evaluatorKeySchedule.relinearizationCrpRoot !==
        crpRoots.relinearizationCrpRoot
    ) {
        throw new Error(
            'evaluatorKeySchedule.relinearizationCrpRoot must match commonRandomness public derivations.',
        );
    }
    if (evaluatorKeySchedule.galoisKeyCrpRoot !== crpRoots.galoisKeyCrpRoot) {
        throw new Error(
            'evaluatorKeySchedule.galoisKeyCrpRoot must match commonRandomness public derivations.',
        );
    }
};

const resolveThresholdShareCommitments = (
    input: SetupPackageInput,
): ThresholdShareCommitmentSet => {
    const materialEncoding = (
        input.vssCoefficientCommitmentMaterial as Readonly<
            Record<string, unknown>
        >
    ).materialEncoding;
    if (
        materialEncoding ===
            'binary-chunked-full-public-setup-commitment-values' &&
        input.thresholdShareCommitments !== undefined
    ) {
        return input.thresholdShareCommitments as ThresholdShareCommitmentSet;
    }
    const derivedThresholdShareCommitments = deriveThresholdShareCommitments({
        setupContext: input.setupContext,
        vssCoefficientCommitments: input.vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial:
            input.vssCoefficientCommitmentMaterial,
        ...(input.transportedVssCoefficientCommitmentMaterial === undefined
            ? {}
            : {
                  transportedVssCoefficientCommitmentMaterial:
                      input.transportedVssCoefficientCommitmentMaterial,
              }),
    });
    if (input.thresholdShareCommitments === undefined) {
        return derivedThresholdShareCommitments;
    }
    if (
        canonicalJson(input.thresholdShareCommitments) !==
        canonicalJson(derivedThresholdShareCommitments)
    ) {
        throw new Error(
            'thresholdShareCommitments must match the verifier-derived commitments from VSS coefficient material.',
        );
    }

    return derivedThresholdShareCommitments;
};

const positiveSafeIntegerField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue <= 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a positive safe integer.`,
        );
    }

    return fieldValue;
};

const protocolHashArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): readonly ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a string.`,
            );
        }
        assertProtocolHash(
            item,
            `${objectPath}.${fieldName}.${String(itemIndex)}`,
        );

        return item;
    });
};

const transportedMaterialObject = (
    material: Readonly<Record<string, unknown>>,
    objectPath: string,
    rootFieldName: string,
    objectName: string,
    objectRole: string,
): SetupCertificateTransportedObjectInput => ({
    objectName,
    objectRole,
    objectRoot: hashField(material, rootFieldName, objectPath),
    byteLength: positiveSafeIntegerField(
        material,
        'totalByteLength',
        objectPath,
    ),
    fullObjectHash: hashField(material, 'fullObjectHash', objectPath),
    chunkRoot: hashField(material, 'chunkRoot', objectPath),
    chunkHashes: protocolHashArrayField(material, 'chunkHashes', objectPath),
});

type TransportedProofMaterialFieldNames = Readonly<{
    readonly byteLength: string;
    readonly fullObjectHash: string;
    readonly chunkRoot: string;
    readonly chunkHashes: string;
}>;

const plainTransportedProofMaterialFields: TransportedProofMaterialFieldNames =
    {
        byteLength: 'totalByteLength',
        fullObjectHash: 'fullObjectHash',
        chunkRoot: 'chunkRoot',
        chunkHashes: 'chunkHashes',
    };

const proofPrefixedTransportedProofMaterialFields: TransportedProofMaterialFieldNames =
    {
        byteLength: 'proofTotalByteLength',
        fullObjectHash: 'proofFullObjectHash',
        chunkRoot: 'proofChunkRoot',
        chunkHashes: 'proofChunkHashes',
    };

const transportedProofMaterialObjects = (
    materialSetValue: unknown,
    materialSetFieldName: string,
    objectName: string,
    objectRole: string,
    fieldNames: TransportedProofMaterialFieldNames,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (materialSetValue === undefined) {
        return [];
    }
    const materialSet = assertObjectRecord(
        materialSetValue,
        materialSetFieldName,
    );
    const proofMaterials = materialSet.proofMaterials;
    if (!Array.isArray(proofMaterials)) {
        throw new TypeError(
            `${materialSetFieldName}.proofMaterials must be an array.`,
        );
    }

    return proofMaterials.map((proofMaterialValue, proofMaterialIndex) => {
        const objectPath = `${materialSetFieldName}.proofMaterials.${String(proofMaterialIndex)}`;
        const proofMaterial = assertObjectRecord(
            proofMaterialValue,
            objectPath,
        );

        return {
            objectName,
            objectRole,
            objectRoot: hashField(
                proofMaterial,
                'proofMaterialRoot',
                objectPath,
            ),
            byteLength: positiveSafeIntegerField(
                proofMaterial,
                fieldNames.byteLength,
                objectPath,
            ),
            fullObjectHash: hashField(
                proofMaterial,
                fieldNames.fullObjectHash,
                objectPath,
            ),
            chunkRoot: hashField(
                proofMaterial,
                fieldNames.chunkRoot,
                objectPath,
            ),
            chunkHashes: protocolHashArrayField(
                proofMaterial,
                fieldNames.chunkHashes,
                objectPath,
            ),
        };
    });
};

const transportedMaterialObjects = (
    materialSetValue: unknown,
    materialSetFieldName: string,
    materialArrayFieldName: string,
    rootFieldName: string,
    objectName: string,
    objectRole: string,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (materialSetValue === undefined) {
        return [];
    }
    const materialSet = assertObjectRecord(
        materialSetValue,
        materialSetFieldName,
    );
    const materials = materialSet[materialArrayFieldName];
    if (!Array.isArray(materials)) {
        throw new TypeError(
            `${materialSetFieldName}.${materialArrayFieldName} must be an array.`,
        );
    }

    return materials.map((materialValue, materialIndex) =>
        transportedMaterialObject(
            assertObjectRecord(
                materialValue,
                `${materialSetFieldName}.${materialArrayFieldName}.${String(materialIndex)}`,
            ),
            `${materialSetFieldName}.${materialArrayFieldName}.${String(materialIndex)}`,
            rootFieldName,
            objectName,
            objectRole,
        ),
    );
};

const transportedPublicKeyShareMaterialObject = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (input.transportedPublicKeyShareMaterial === undefined) {
        return [];
    }
    const transportedMaterial = assertObjectRecord(
        input.transportedPublicKeyShareMaterial,
        'transportedPublicKeyShareMaterial',
    );
    const packageMaterialRoot = hashField(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
    );

    return [
        {
            objectName: 'publicKeyShareMaterial',
            objectRole: 'public-key-share-material',
            objectRoot: packageMaterialRoot,
            byteLength: positiveSafeIntegerField(
                transportedMaterial,
                'totalByteLength',
                'transportedPublicKeyShareMaterial',
            ),
            fullObjectHash: hashField(
                transportedMaterial,
                'fullObjectHash',
                'transportedPublicKeyShareMaterial',
            ),
            chunkRoot: hashField(
                transportedMaterial,
                'chunkRoot',
                'transportedPublicKeyShareMaterial',
            ),
            chunkHashes: protocolHashArrayField(
                transportedMaterial,
                'chunkHashes',
                'transportedPublicKeyShareMaterial',
            ),
        },
    ];
};

const setupCertificateTransportedObjectsFromPackageInput = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => [
    ...transportedPublicKeyShareMaterialObject(input),
    ...transportedProofMaterialObjects(
        input.transportedSameSecretProofMaterial,
        'transportedSameSecretProofMaterial',
        'sameSecretProofMaterial',
        'same-secret-proof-material',
        plainTransportedProofMaterialFields,
    ),
    ...transportedProofMaterialObjects(
        input.transportedPublicKeyShareProofMaterial,
        'transportedPublicKeyShareProofMaterial',
        'publicKeyShareProofMaterial',
        'public-key-share-proof-material',
        plainTransportedProofMaterialFields,
    ),
    ...transportedProofMaterialObjects(
        input.transportedEvaluationKeyShareProofMaterial,
        'transportedEvaluationKeyShareProofMaterial',
        'evaluationKeyShareProofMaterial',
        'evaluation-key-share-proof-material',
        proofPrefixedTransportedProofMaterialFields,
    ),
    ...transportedMaterialObjects(
        input.transportedEvaluationKeyShareComponentMaterial,
        'transportedEvaluationKeyShareComponentMaterial',
        'componentMaterials',
        'keySwitchComponentMaterialRoot',
        'evaluationKeyShareComponentMaterial',
        'evaluation-key-share-component-material',
    ),
    ...transportedMaterialObjects(
        input.transportedPublicEvaluationKeyMaterial,
        'transportedPublicEvaluationKeyMaterial',
        'publicEvaluationKeyMaterials',
        'publicEvaluationKeyMaterialRoot',
        'publicEvaluationKeyMaterial',
        'public-evaluation-key-runtime-material',
    ),
];

const resolveSetupCertificateRecords = (
    input: SetupPackageInput,
): SetupPackageCertificateRecords => {
    if (input.setupCertificateInput !== undefined) {
        if (
            input.setupCommitmentSecurityCertificate !== undefined ||
            input.setupTransportCertificate !== undefined ||
            input.setupProofAccountingCertificate !== undefined ||
            input.heSecurityCertificate !== undefined
        ) {
            throw new Error(
                'setupCertificateInput must not be mixed with prebuilt setup certificate records.',
            );
        }

        const transportedObjects =
            setupCertificateTransportedObjectsFromPackageInput(input);

        return createSetupCertificates({
            ...input.setupCertificateInput,
            vssCoefficientCommitmentMaterial:
                input.vssCoefficientCommitmentMaterial,
            transport:
                transportedObjects.length === 0
                    ? input.setupCertificateInput.transport
                    : {
                          ...input.setupCertificateInput.transport,
                          transportedObjects: [
                              ...(input.setupCertificateInput.transport
                                  .transportedObjects ?? []),
                              ...transportedObjects,
                          ],
                      },
        });
    }

    if (
        input.setupCommitmentSecurityCertificate === undefined ||
        input.setupTransportCertificate === undefined ||
        input.setupProofAccountingCertificate === undefined ||
        input.heSecurityCertificate === undefined
    ) {
        throw new Error(
            'setupCertificateInput or all setup certificate records are required.',
        );
    }

    return {
        setupCommitmentSecurityCertificate:
            input.setupCommitmentSecurityCertificate,
        setupTransportCertificate: input.setupTransportCertificate,
        setupProofAccountingCertificate: input.setupProofAccountingCertificate,
        heSecurityCertificate: input.heSecurityCertificate,
    };
};

const assertCertificateBindings = (
    certificates: SetupPackageCertificateRecords,
): void => {
    assertObjectType(
        certificates.setupCommitmentSecurityCertificate,
        'setupCommitmentSecurityCertificate',
        'SetupCommitmentSecurityCertificate',
    );
    hashField(
        certificates.setupCommitmentSecurityCertificate,
        'setupCommitmentSecurityCertificateHash',
        'setupCommitmentSecurityCertificate',
    );
    assertObjectType(
        certificates.setupTransportCertificate,
        'setupTransportCertificate',
        'SetupTransportCertificate',
    );
    hashField(
        certificates.setupTransportCertificate,
        'setupTransportCertificateHash',
        'setupTransportCertificate',
    );
    assertObjectType(
        certificates.setupProofAccountingCertificate,
        'setupProofAccountingCertificate',
        'SetupProofAccountingCertificate',
    );
    hashField(
        certificates.setupProofAccountingCertificate,
        'setupProofAccountingCertificateHash',
        'setupProofAccountingCertificate',
    );
    assertObjectType(
        certificates.heSecurityCertificate,
        'heSecurityCertificate',
        'BgvHeSecurityCertificate',
    );
    hashField(
        certificates.heSecurityCertificate,
        'heSecurityCertificateHash',
        'heSecurityCertificate',
    );
};

const assertGaloisScheduleCovered = (input: SetupPackageInput): void => {
    const requiredGaloisKeySchedule =
        input.evaluatorKeySchedule.requiredGaloisKeySchedule;
    if (!Array.isArray(requiredGaloisKeySchedule)) {
        throw new TypeError(
            'evaluatorKeySchedule.requiredGaloisKeySchedule must be an array.',
        );
    }
    const availableBatchKeys = new Set(
        input.galoisKeyShareBatches.flatMap((batch) =>
            batch.galoisKeyShareMaterialRecords.map(
                (materialRecord) =>
                    `${String(materialRecord.rotation)}:${String(materialRecord.level)}`,
            ),
        ),
    );
    for (const scheduleEntry of requiredGaloisKeySchedule as readonly RequiredGaloisKeyScheduleEntry[]) {
        const scheduleKey = `${String(scheduleEntry.rotation)}:${String(
            scheduleEntry.level,
        )}`;
        if (!availableBatchKeys.has(scheduleKey)) {
            throw new Error(
                `galoisKeyShareBatches must include scheduled rotation ${String(scheduleEntry.rotation)} level ${String(scheduleEntry.level)}.`,
            );
        }
    }
};

const validateInput = (
    input: SetupPackageInput,
    certificates: SetupPackageCertificateRecords,
    thresholdShareCommitments: ThresholdShareCommitmentSet,
): void => {
    assertCommonBindings(input);
    assertObjectType(
        thresholdShareCommitments,
        'thresholdShareCommitments',
        'ThresholdShareCommitmentSet',
    );
    hashField(
        thresholdShareCommitments,
        'thresholdShareCommitmentRoot',
        'thresholdShareCommitments',
    );
    assertKeyRecordBindings(input);
    assertCommonRandomnessPublicDerivationsBindPackageInput(input);
    assertCertificateBindings(certificates);
    assertGaloisScheduleCovered(input);
};

const contextFieldsForCertificate = (
    setupContext: CollectiveBgvSetupContext,
): JsonRecord =>
    Object.fromEntries(
        contextFieldNames.map((fieldName) => [
            fieldName,
            setupContext[fieldName],
        ]),
    );

const qSharePrimesFromPublicKeyShares = (
    publicKeyShares: PublicKeyShareSet,
    expectedRnsLimbCount: number,
): readonly number[] => {
    const shareRecords = [...publicKeyShares.shareRecords].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (shareRecords.length !== publicKeyShares.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one record per participant.',
        );
    }
    const firstShareRecord = shareRecords[0];
    if (firstShareRecord === undefined) {
        throw new Error('publicKeyShares must contain at least one record.');
    }
    const qSharePrimes =
        firstShareRecord.shareCoefficientVectorHash512ByLimb.map(
            (coefficientVectorHash, rnsLimbIndex) => {
                if (
                    coefficientVectorHash.rnsLimbIndex !== rnsLimbIndex ||
                    coefficientVectorHash.component !== 'b_i' ||
                    !Number.isSafeInteger(coefficientVectorHash.rnsPrime) ||
                    coefficientVectorHash.rnsPrime <= 0
                ) {
                    throw new Error(
                        'publicKeyShares coefficient hash limbs must expose accepted Q_share primes in order.',
                    );
                }

                return coefficientVectorHash.rnsPrime;
            },
        );
    if (qSharePrimes.length !== expectedRnsLimbCount) {
        throw new Error('publicKeyShares RNS limbs must match material roots.');
    }
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        if (
            shareRecord.trusteeRosterPosition !== expectedRosterPosition ||
            shareRecord.shareCoefficientVectorHash512ByLimb.length !==
                qSharePrimes.length
        ) {
            throw new Error(
                'publicKeyShares share records must have contiguous roster positions and complete RNS limbs.',
            );
        }
        shareRecord.shareCoefficientVectorHash512ByLimb.forEach(
            (coefficientVectorHash, rnsLimbIndex) => {
                if (
                    coefficientVectorHash.rnsLimbIndex !== rnsLimbIndex ||
                    coefficientVectorHash.component !== 'b_i' ||
                    coefficientVectorHash.rnsPrime !==
                        qSharePrimes[rnsLimbIndex]
                ) {
                    throw new Error(
                        'publicKeyShares share records must agree on Q_share primes.',
                    );
                }
            },
        );
    });

    return qSharePrimes;
};

const derivedCollectivePublicKey = (
    input: SetupPackageInput,
): CollectivePublicKey => {
    if (
        Object.prototype.hasOwnProperty.call(input, 'collectivePublicKey') &&
        (input as Readonly<{ readonly collectivePublicKey?: unknown }>)
            .collectivePublicKey !== undefined
    ) {
        throw new Error(
            'collectivePublicKey is derived from accepted public-key material and must not be supplied by callers.',
        );
    }
    const publicKeyShareMaterial =
        input.publicKeyShareMaterial as SetupPackagePublicKeyShareMaterialSet;
    const qSharePrimes = qSharePrimesFromPublicKeyShares(
        input.publicKeyShares,
        publicKeyShareMaterial.rnsLimbCount,
    );
    const commonCollectivePublicKeyInput = {
        setupContext: input.setupContext,
        qSharePrimes,
        participantCount: input.publicKeyShares.participantCount,
        ringDegree: publicKeyShareMaterial.ringDegree,
        publicMatrixSeedHash: publicKeyShareMaterial.publicMatrixSeedHash,
        publicKeyCrpRoot: publicKeyShareMaterial.publicKeyCrpRoot,
        publicAPolynomialRoot: publicKeyShareMaterial.publicAPolynomialRoot,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs as SameSecretProofSet,
        publicKeyShares: input.publicKeyShares,
        publicKeyShareProofs: input.publicKeyShareProofs,
        publicKeyShareMaterial,
        publicKeyShareSuccinctProofs:
            input.publicKeyShareSuccinctProofs as PublicKeyShareSuccinctProofSet,
    } as const;

    if (
        publicKeyShareMaterial.materialEncoding ===
        publicKeyShareMaterialTransportEncoding
    ) {
        if (input.transportedPublicKeyShareMaterial === undefined) {
            throw new Error(
                'transportedPublicKeyShareMaterial is required when publicKeyShareMaterial is binary-chunked.',
            );
        }

        return createCollectivePublicKeyFromTransportedPublicKeyShareMaterial({
            ...commonCollectivePublicKeyInput,
            publicKeyShareMaterial,
            transportedPublicKeyShareMaterial:
                input.transportedPublicKeyShareMaterial,
        });
    }

    return createCollectivePublicKey({
        ...commonCollectivePublicKeyInput,
        publicKeyShareMaterial,
    });
};

const galoisBatchRootEntries = (
    galoisKeyShareBatches: readonly GaloisKeyShareBatch[],
): readonly JsonRecord[] =>
    galoisKeyShareBatches.map((batch, batchIndex) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: hashField(
            batch,
            'galoisKeyShareBatchRoot',
            `galoisKeyShareBatches.${String(batchIndex)}`,
        ),
    }));

const setupKeyCorrectnessCertificateBody = (
    input: SetupPackageInputWithDerivedCollectivePublicKey,
    certificates: SetupPackageCertificateRecords,
): SetupKeyCorrectnessCertificateBody => {
    const collectivePublicKeyRoot = hashField(
        input.collectivePublicKey,
        'collectivePublicKeyRoot',
        'collectivePublicKey',
    );
    const evaluationKeySetHash = hashField(
        input.evaluationKeys,
        'evaluationKeySetHash',
        'evaluationKeys',
    );
    const publicKeyShareMaterialSetRoot = hashField(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
    );
    const publicKeyShareSuccinctProofSetRoot = hashField(
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofSetRoot',
        'publicKeyShareSuccinctProofs',
    );

    return {
        objectType: 'SetupKeyCorrectnessCertificate',
        objectVersion: 1,
        setupProfileId,
        ...contextFieldsForCertificate(input.setupContext),
        setupProofProfileBinding:
            'fixed-setup-proof-profile-bound-by-setup-proof-accounting-certificate',
        keyCorrectnessScope:
            'collective-public-key-and-public-evaluation-key-roots-derived-from-proof-bearing-setup-records',
        keyCorrectnessTheorem: {
            theoremStatus:
                'repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots',
            claimDependency:
                'terminal accepted setup verifies these roots before returning the accepted setup handoff',
            checkedByVerifier: [
                'collective public-key coefficients are recomputed from publicKeyShareMaterial records and verified source roots',
                'collectivePublicKeyRoot is canonical and matches the top-level setup package root',
                'evaluationKeySetHash is canonical and binds the frozen evaluator schedule, relinearization rounds, and Galois batch records',
                'transported public evaluation-key runtime material is verified against evaluationKeys when supplied',
                'generic key-switch material and unscheduled Galois keys are refused for the first profile',
            ],
            activeMaliciousPrototypeBoundary:
                'malformed roots, reordered trustee records, stale schedules, missing proof material, inconsistent collective public-key material, and unscheduled evaluation keys are refused before accepted runtime loading',
        },
        collectivePublicKey: {
            status: 'collective-public-key-coefficients-recomputed-from-public-key-share-material-and-succinct-proof-roots',
            collectivePublicKeyRoot,
            sourceRoots: {
                publicKeyShareSetRoot: hashField(
                    input.publicKeyShares,
                    'publicKeyShareSetRoot',
                    'publicKeyShares',
                ),
                publicKeyShareProofSetRoot: hashField(
                    input.publicKeyShareProofs,
                    'publicKeyShareProofSetRoot',
                    'publicKeyShareProofs',
                ),
                publicKeyShareMaterialSetRoot,
                publicKeyShareSuccinctProofSetRoot,
            },
        },
        publicEvaluationKeys: {
            status: 'public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records',
            evaluationKeySetHash,
            evaluatorKeyScheduleRoot: hashField(
                input.evaluatorKeySchedule,
                'evaluatorKeyScheduleRoot',
                'evaluatorKeySchedule',
            ),
            relinearizationKeyShareRoundsRoot: hashField(
                input.relinearizationKeyShareRounds,
                'relinearizationKeyShareRoundsRoot',
                'relinearizationKeyShareRounds',
            ),
            galoisKeyShareBatchRoots: galoisBatchRootEntries(
                input.galoisKeyShareBatches,
            ),
            requiredGaloisSetHash: hashField(
                input.evaluatorKeySchedule,
                'requiredGaloisSetHash',
                'evaluatorKeySchedule',
            ),
        },
        certificateDependencies: {
            setupProofAccountingCertificateHash: hashField(
                certificates.setupProofAccountingCertificate,
                'setupProofAccountingCertificateHash',
                'setupProofAccountingCertificate',
            ),
            heSecurityCertificateHash: hashField(
                certificates.heSecurityCertificate,
                'heSecurityCertificateHash',
                'heSecurityCertificate',
            ),
        },
        claimBoundary:
            'key-correctness theorem is accepted for verified roots, loaded runtime material, and terminal accepted setup handoff construction',
    };
};

const createSetupKeyCorrectnessCertificate = (
    input: SetupPackageInputWithDerivedCollectivePublicKey,
    certificates: SetupPackageCertificateRecords,
): SetupKeyCorrectnessCertificate => {
    const certificateBody = setupKeyCorrectnessCertificateBody(
        input,
        certificates,
    );

    return {
        ...certificateBody,
        setupKeyCorrectnessCertificateHash: deriveProtocolHash(
            'SetupKeyCorrectnessCertificateHash',
            certificateBody,
        ),
    };
};

const packageDeclaresPublicRuntimeMaterial = (
    setupPackage: Readonly<Record<string, unknown>>,
): boolean => {
    if (setupPackage.collectivePublicKey !== undefined) {
        return true;
    }
    const evaluationKeys = setupPackage.evaluationKeys;

    return (
        typeof evaluationKeys === 'object' &&
        evaluationKeys !== null &&
        !Array.isArray(evaluationKeys) &&
        Object.keys(evaluationKeys).length > 0
    );
};

const activeStaticSetupTheoremCertificateBody = (
    setupPackage: Readonly<Record<string, unknown>>,
): ActiveStaticSetupTheoremCertificateBody => {
    const setupContext = assertObjectRecord(
        setupPackage.setupContext,
        'setupPackage.setupContext',
    );
    const evaluationKeysDeclared =
        packageDeclaresPublicRuntimeMaterial(setupPackage);

    return {
        objectType: 'ActiveStaticSetupTheoremCertificate',
        objectVersion: 1,
        setupProfileId,
        ...contextFieldsForCertificate(
            setupContext as unknown as CollectiveBgvSetupContext,
        ),
        adversaryModel: {
            corruptionTiming: 'active-static',
            maliciousBehavior:
                'arbitrary-invalid-public-setup-artifacts-and-abort',
            secretConfidentialityCorruptTrusteeBound:
                firstProfileDecryptionThreshold - 1,
            fullRosterSetupCompletionRequired: true,
        },
        livenessModel: {
            model: 'secure-with-abort',
            setupCompletionQuorum: firstProfileSetupCompletionQuorum,
            participantCount: firstProfileParticipantCount,
            acceptedAbortEvents: [
                'missing required setup phase object',
                'malformed public setup object',
                'invalid private VSS acceptance state',
                'invalid setup proof or proof material root',
                'invalid collective public-key or evaluation-key root',
                'unsupported target-decryption readiness claim',
            ],
            notClaimed: [
                'guaranteed output delivery',
                'identifiable abort',
                'post-setup target decryption',
                'production audit readiness',
            ],
        },
        verifiedSetupGates: [
            'setup context and package hash bind the ceremony, roster, manifest, profile, Q_share, commitment profile, and setup epoch',
            'full-roster common randomness commit/reveal records derive public setup matrices before proof and key verification',
            'public VSS coefficient commitments and recipient-local signed acceptances are checked before threshold-share commitment derivation',
            'threshold-share commitment roots are verifier-derived from public VSS commitments, not source-trustee supplied',
            'same-secret, public-key share, relinearization, and Galois proof records are verified before key roots are accepted',
            'collective public-key coefficients and public evaluation-key roots are verifier-recomputed from proof-bearing setup records',
            'setup commitment, proof-accounting, transport, HE, and key-correctness certificates are root-bound package objects',
            'generic key-switch material, unscheduled Galois keys, raw setup witnesses, raw shares, external aggregate public-key material, and premature target-decryption readiness are refused',
        ],
        dependencyHashes: {
            setupCommitmentSecurityCertificateHash: hashField(
                setupPackage,
                'setupCommitmentSecurityCertificateHash',
                'setupPackage',
            ),
            setupTransportCertificateHash: hashField(
                setupPackage,
                'setupTransportCertificateHash',
                'setupPackage',
            ),
            setupProofAccountingCertificateHash: hashField(
                setupPackage,
                'setupProofAccountingCertificateHash',
                'setupPackage',
            ),
            heSecurityCertificateHash: hashField(
                setupPackage,
                'heSecurityCertificateHash',
                'setupPackage',
            ),
            setupKeyCorrectnessCertificateHash: optionalTopLevelHashValue(
                setupPackage,
                'setupKeyCorrectnessCertificateHash',
            ),
        },
        terminalRoots: {
            thresholdShareCommitmentRoot: optionalTopLevelHashValue(
                setupPackage,
                'thresholdShareCommitmentRoot',
            ),
            sameSecretProofSetRoot: optionalNestedHashValue(
                setupPackage,
                'sameSecretProofs',
                'sameSecretProofSetRoot',
            ),
            publicKeyShareMaterialSetRoot: optionalNestedHashValue(
                setupPackage,
                'publicKeyShareMaterial',
                'publicKeyShareMaterialSetRoot',
            ),
            publicKeyShareSuccinctProofSetRoot: optionalNestedHashValue(
                setupPackage,
                'publicKeyShareSuccinctProofs',
                'publicKeyShareSuccinctProofSetRoot',
            ),
            collectivePublicKeyRoot: optionalNestedHashValue(
                setupPackage,
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ),
            evaluatorKeyScheduleRoot: optionalNestedHashValue(
                setupPackage,
                'evaluatorKeySchedule',
                'evaluatorKeyScheduleRoot',
            ),
            evaluationKeySetHash: optionalNestedHashValue(
                setupPackage,
                'evaluationKeys',
                'evaluationKeySetHash',
            ),
            publicEvaluationKeyMaterialRoot: optionalNestedHashValue(
                setupPackage,
                'evaluationKeys',
                'publicEvaluationKeyMaterialRoot',
            ),
        },
        referenceRows: [
            {
                document: 'BCD25_Threshold (Fully) Homomorphic Encryption',
                localReferencePath:
                    'reference-documents/BCD25_Threshold (Fully) Homomorphic Encryption.txt',
                sections: [
                    'active-with-abort security model',
                    'static malicious adversaries',
                    'threshold FHE setup and abort boundaries',
                ],
            },
            {
                document:
                    'LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General',
                localReferencePath:
                    'reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt',
                sections: [
                    'Fiat-Shamir with aborts',
                    'commit-and-prove simulatability',
                    'knowledge soundness',
                ],
            },
            {
                document:
                    'BFM25_Threshold FHE with Efficient Asynchronous Decryption',
                localReferencePath:
                    'reference-documents/BFM25_Threshold FHE with Efficient Asynchronous Decryption.txt',
                sections: [
                    'malicious participant detection',
                    'setup preprocessing',
                    'abort behavior',
                ],
            },
        ],
        claimBoundary: {
            certificateStatus:
                'active-static-secure-with-abort-theorem-accepted',
            evaluationKeyCorrectnessStatus: evaluationKeysDeclared
                ? 'requires-setup-key-correctness-certificate'
                : 'no-public-evaluation-key-runtime-material-declared',
            remainingDependencies: [],
            integrationDependencies: [],
            completionBoundary:
                'external validation, independent audit, and third-party proof review are not setup completion prerequisites',
        },
    };
};

const createActiveStaticSetupTheoremCertificate = (
    setupPackage: Readonly<Record<string, unknown>>,
): ActiveStaticSetupTheoremCertificate => {
    const certificateBody =
        activeStaticSetupTheoremCertificateBody(setupPackage);

    return {
        ...certificateBody,
        activeStaticSetupTheoremCertificateHash: deriveProtocolHash(
            'ActiveStaticSetupTheoremCertificateHash',
            certificateBody,
        ),
    };
};

export const createSetupPackage = (input: SetupPackageInput): SetupPackage => {
    const certificates = resolveSetupCertificateRecords(input);
    const thresholdShareCommitments = resolveThresholdShareCommitments(input);
    validateInput(input, certificates, thresholdShareCommitments);
    const collectivePublicKey = derivedCollectivePublicKey(input);
    const resolvedInput: SetupPackageInputWithDerivedCollectivePublicKey = {
        ...input,
        collectivePublicKey,
    };
    const setupKeyCorrectnessCertificate = createSetupKeyCorrectnessCertificate(
        resolvedInput,
        certificates,
    );

    const privateVssEnvelopeCommitments = publicPrivateVssEnvelopeCommitmentSet(
        input.privateVssEnvelopeCommitments,
    );
    const setupCommitmentSecurityCertificateHash = hashField(
        certificates.setupCommitmentSecurityCertificate,
        'setupCommitmentSecurityCertificateHash',
        'setupCommitmentSecurityCertificate',
    );
    const setupTransportCertificateHash = hashField(
        certificates.setupTransportCertificate,
        'setupTransportCertificateHash',
        'setupTransportCertificate',
    );
    const setupProofAccountingCertificateHash = hashField(
        certificates.setupProofAccountingCertificate,
        'setupProofAccountingCertificateHash',
        'setupProofAccountingCertificate',
    );
    const heSecurityCertificateHash = hashField(
        certificates.heSecurityCertificate,
        'heSecurityCertificateHash',
        'heSecurityCertificate',
    );
    const setupKeyCorrectnessCertificateHash = hashField(
        setupKeyCorrectnessCertificate,
        'setupKeyCorrectnessCertificateHash',
        'setupKeyCorrectnessCertificate',
    );
    const privateVssEnvelopeCommitmentRoot = hashField(
        privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitmentRoot',
        'privateVssEnvelopeCommitments',
    );
    const collectivePublicKeyRoot = hashField(
        collectivePublicKey,
        'collectivePublicKeyRoot',
        'collectivePublicKey',
    );

    const packageWithoutActiveStaticCertificate = {
        objectType: 'SetupPackage',
        objectVersion: 1,
        setupProfileId,
        setupContext: input.setupContext,
        qShare: input.qShare,
        phaseTranscript: input.phaseTranscript,
        commonRandomness: input.commonRandomness,
        vssCoefficientCommitments: input.vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial:
            input.vssCoefficientCommitmentMaterial,
        privateVssEnvelopeCommitments,
        privateVssEnvelopeCommitmentRoot,
        ...(input.vssComplaints === undefined
            ? {}
            : { vssComplaints: input.vssComplaints }),
        vssShareAcceptances: input.vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs,
        publicKeyShares: input.publicKeyShares,
        publicKeyShareProofs: input.publicKeyShareProofs,
        publicKeyShareMaterial: input.publicKeyShareMaterial,
        publicKeyShareSuccinctProofs: input.publicKeyShareSuccinctProofs,
        collectivePublicKey,
        collectivePublicKeyRoot,
        evaluatorKeySchedule: input.evaluatorKeySchedule,
        relinearizationKeyShareRounds: input.relinearizationKeyShareRounds,
        galoisKeyShareBatches: input.galoisKeyShareBatches,
        trusteeEvaluationKeyProofs: input.trusteeEvaluationKeyProofs,
        evaluationKeys: input.evaluationKeys,
        setupCommitmentSecurityCertificate:
            certificates.setupCommitmentSecurityCertificate,
        setupCommitmentSecurityCertificateHash,
        setupTransportCertificate: certificates.setupTransportCertificate,
        setupTransportCertificateHash,
        setupProofAccountingCertificate:
            certificates.setupProofAccountingCertificate,
        setupProofAccountingCertificateHash,
        setupKeyCorrectnessCertificate,
        setupKeyCorrectnessCertificateHash,
        heSecurityCertificate: certificates.heSecurityCertificate,
        heSecurityCertificateHash,
    } as const;
    const activeStaticSetupTheoremCertificate =
        createActiveStaticSetupTheoremCertificate(
            packageWithoutActiveStaticCertificate,
        );
    const activeStaticSetupTheoremCertificateHash = hashField(
        activeStaticSetupTheoremCertificate,
        'activeStaticSetupTheoremCertificateHash',
        'activeStaticSetupTheoremCertificate',
    );
    const packageWithoutHash = {
        ...packageWithoutActiveStaticCertificate,
        activeStaticSetupTheoremCertificate,
        activeStaticSetupTheoremCertificateHash,
    } as const satisfies Omit<SetupPackage, 'setupPackageHash'>;

    return {
        ...packageWithoutHash,
        setupPackageHash: deriveProtocolHash(
            'SetupPackageHash',
            setupPackageHashInput(packageWithoutHash),
        ),
    } satisfies SetupPackage;
};
