import { canonicalJson, deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from './common-randomness-records.js';
import type {
    GaloisKeyShareBatch,
    PublicEvaluationKeySet,
    RelinearizationKeyShareRounds,
} from './evaluation-key-proof-records.js';
import type {
    EvaluatorKeySchedule,
    RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
import type {
    CollectivePublicKey,
    PublicKeyShareProofSet,
    PublicKeyShareLnpProofSet,
    PublicKeyShareMaterialSet,
    PublicKeyShareSet,
} from './public-key-share-records.js';
import { createCollectivePublicKey } from './public-key-share-records.js';
import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
} from './same-secret-consistency-records.js';
import {
    createSetupCertificates,
    type SetupCertificatesInput,
} from './setup-certificates.js';
import type { SetupPhaseRecord } from './setup-phase-records.js';
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from './threshold-share-commitments.js';
import type {
    VssCoefficientCommitmentMaterialSet,
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

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial:
        | VssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet | JsonRecord;
    readonly thresholdShareCommitments?:
        | ThresholdShareCommitmentSet
        | JsonRecord;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet | JsonRecord;
    readonly publicKeyShareLnpProofs: PublicKeyShareLnpProofSet | JsonRecord;
    readonly collectivePublicKey?: never;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly evaluationKeys: PublicEvaluationKeySet;
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
            | VssCoefficientCommitmentMaterialSet
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
        readonly publicKeyShareMaterial: PublicKeyShareMaterialSet | JsonRecord;
        readonly publicKeyShareLnpProofs:
            | PublicKeyShareLnpProofSet
            | JsonRecord;
        readonly collectivePublicKey: CollectivePublicKey | JsonRecord;
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly evaluatorKeySchedule: EvaluatorKeySchedule;
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly evaluationKeys: PublicEvaluationKeySet;
        readonly setupCommitmentSecurityCertificate: JsonRecord;
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificate: JsonRecord;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificate: JsonRecord;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificate: SetupKeyCorrectnessCertificate;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly heSecurityCertificate: JsonRecord;
        readonly heSecurityCertificateHash: ProtocolHash;
        readonly setupPackageHash: ProtocolHash;
    }
>;

type SetupPackageInputWithDerivedCollectivePublicKey = Omit<
    SetupPackageInput,
    'collectivePublicKey'
> &
    Readonly<{
        readonly collectivePublicKey: CollectivePublicKey;
    }>;

const setupProfileId = 'CollectiveBgvSetup-v1';
const protocolHashPattern = /^[0-9a-f]{128}$/u;
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
    ['galoisKeyBatchProofs', 12],
    ['setupPackageAssembly', 13],
    ['setupPackageVerification', 14],
] as const;

const forbiddenPackageFieldNames = new Set([
    'aggregateOpening',
    'aggregateOpeningColumns',
    'carryWitnessesDecimal',
    'externallySuppliedSetupMaterial',
    'coefficientMessage',
    'coefficientMessagesByShamirIndex',
    'coefficientOpenings',
    'decryptionShareWitness',
    'lattigoGaloisKey',
    'lattigoPublicKey',
    'lattigoRelinearizationKey',
    'lattigoSetupMaterial',
    'openingColumnsDecimal',
    'openingRandomnessByLimb',
    'proofGeneration',
    'proofWitness',
    'proofWitnesses',
    'randomnessByColumn',
    'rawAggregateThresholdShare',
    'rawSecret',
    'rawSecretShare',
    'rawShamirShare',
    'rawShamirShares',
    'rawShare',
    'rawShares',
    'roundOneAggregateSourceCoefficientsByDigit',
    'secretCoefficients',
    'setupPrivateWitness',
    'setupSeed',
    'setupSeedHash',
    'shareValues',
]);
const legacyExternalSetupRoleFieldNameTokens = [
    'setup',
    'authority',
    'central',
    'trusted',
];
const fieldNameSuggestsLegacyExternalSetupRole = (
    fieldName: string,
): boolean => {
    const lowercaseFieldName = fieldName.toLowerCase();
    return legacyExternalSetupRoleFieldNameTokens.every((token) =>
        lowercaseFieldName.includes(token),
    );
};

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

export const collectForbiddenSetupPackageAssemblyFieldPaths = (
    value: unknown,
    objectPath = 'setupPackage',
): string[] => {
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenSetupPackageAssemblyFieldPaths(
                item,
                `${objectPath}.${String(itemIndex)}`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    return Object.entries(value).flatMap(([fieldName, fieldValue]) => {
        const fieldPath = `${objectPath}.${fieldName}`;
        if (
            forbiddenPackageFieldNames.has(fieldName) ||
            fieldNameSuggestsLegacyExternalSetupRole(fieldName)
        ) {
            return [fieldPath];
        }

        return collectForbiddenSetupPackageAssemblyFieldPaths(
            fieldValue,
            fieldPath,
        );
    });
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
        input.publicKeyShareLnpProofs,
        'publicKeyShareLnpProofs',
        'PublicKeyShareLnpProofSet',
    );
    hashField(
        input.publicKeyShareLnpProofs,
        'publicKeyShareLnpProofSetRoot',
        'publicKeyShareLnpProofs',
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
        input.evaluationKeys,
        'evaluationKeys',
        'PublicEvaluationKeySet',
    );
    hashField(input.evaluationKeys, 'evaluationKeySetHash', 'evaluationKeys');
};

const resolveThresholdShareCommitments = (
    input: SetupPackageInput,
): ThresholdShareCommitmentSet => {
    const derivedThresholdShareCommitments = deriveThresholdShareCommitments({
        setupContext: input.setupContext,
        vssCoefficientCommitments: input.vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial:
            input.vssCoefficientCommitmentMaterial,
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

        return createSetupCertificates({
            ...input.setupCertificateInput,
            vssCoefficientCommitmentMaterial:
                input.vssCoefficientCommitmentMaterial,
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
            batch.galoisKeyShareProofs.map(
                (proof) => `${String(proof.rotation)}:${String(proof.level)}`,
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

const qSharePrimesFromPublicKeyShareMaterial = (
    publicKeyShareMaterial: PublicKeyShareMaterialSet,
): readonly number[] => {
    const [firstMaterialRecord] = publicKeyShareMaterial.shareMaterialRecords;
    if (firstMaterialRecord === undefined) {
        throw new Error(
            'publicKeyShareMaterial must contain source share material records.',
        );
    }

    return firstMaterialRecord.shareCoefficientVectorsByLimb.map(
        (coefficientVector, rnsLimbIndex) => {
            if (
                coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                !Number.isSafeInteger(coefficientVector.rnsPrime) ||
                coefficientVector.rnsPrime <= 0
            ) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vector limbs must expose accepted Q_share primes in order.',
                );
            }

            return coefficientVector.rnsPrime;
        },
    );
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
        input.publicKeyShareMaterial as PublicKeyShareMaterialSet;

    return createCollectivePublicKey({
        setupContext: input.setupContext,
        qSharePrimes: qSharePrimesFromPublicKeyShareMaterial(
            publicKeyShareMaterial,
        ),
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
        publicKeyShareLnpProofs:
            input.publicKeyShareLnpProofs as PublicKeyShareLnpProofSet,
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
    const publicKeyShareLnpProofSetRoot = hashField(
        input.publicKeyShareLnpProofs,
        'publicKeyShareLnpProofSetRoot',
        'publicKeyShareLnpProofs',
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
        collectivePublicKey: {
            status: 'collective-public-key-root-bound-to-public-key-share-material-and-LNP-proof-roots',
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
                publicKeyShareLnpProofSetRoot,
            },
        },
        publicEvaluationKeys: {
            status: 'public-evaluation-key-roots-bound-to-frozen-schedule-and-proof-bearing-relinearization-and-galois-records',
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
            'claim-bearing key correctness still requires proof-accounting and theorem closure before accepted setup can close',
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

    const packageWithoutHash = {
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
        publicKeyShareLnpProofs: input.publicKeyShareLnpProofs,
        collectivePublicKey,
        collectivePublicKeyRoot,
        evaluatorKeySchedule: input.evaluatorKeySchedule,
        relinearizationKeyShareRounds: input.relinearizationKeyShareRounds,
        galoisKeyShareBatches: input.galoisKeyShareBatches,
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
    } as const satisfies Omit<SetupPackage, 'setupPackageHash'>;
    const forbiddenFieldPaths =
        collectForbiddenSetupPackageAssemblyFieldPaths(packageWithoutHash);
    if (forbiddenFieldPaths.length > 0) {
        throw new Error(
            `setupPackage includes forbidden raw setup fields: ${forbiddenFieldPaths.join(', ')}`,
        );
    }

    return {
        ...packageWithoutHash,
        setupPackageHash: deriveProtocolHash(
            'SetupPackageHash',
            setupPackageHashInput(packageWithoutHash),
        ),
    } satisfies SetupPackage;
};
