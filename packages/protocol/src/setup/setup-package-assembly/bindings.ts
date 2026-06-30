import { canonicalJson, deriveProtocolHash } from "@sealed-lattice/crypto";
import type { ProtocolHash } from "@sealed-lattice/types";

import {
    verifyCompactVssShareLinkageProofMaterialSet,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageProofMaterialSet,
    type CompactVssShareLinkageStatement,
} from "../compact-vss-commitments.js";
import type { RequiredGaloisKeyScheduleEntry } from "../evaluator-key-schedule.js";
import {
    verifyCompactVssSameSecretBridgeProofMaterialSet,
    type CompactVssSameSecretBridgeProofMaterialSet,
    type CompactVssSameSecretBridgeStatementSet,
    type SameSecretProofSet,
    type TransportedSameSecretProofMaterialSet,
} from "../same-secret-consistency-records.js";
import type { SetupPhaseRecord } from "../setup-phase-records.js";
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from "../threshold-share-commitments.js";
import type { CollectiveBgvSetupContext } from "../vss-share-verification-records.js";

import {
    assertCommonRandomnessContextMatches,
    assertContext,
    assertContextMatches,
    assertObjectRecord,
    assertObjectType,
    hashField,
    requiredSetupPhases,
    setupProfileId,
} from "./constants-and-assertions.js";
import type {
    SetupPackageCertificateRecords,
    SetupPackageInput,
} from "./types.js";

const assertPhaseTranscript = (
    setupContext: CollectiveBgvSetupContext,
    phaseTranscript: readonly SetupPhaseRecord[],
): void => {
    if (phaseTranscript.length !== requiredSetupPhases.length) {
        throw new Error(
            "phaseTranscript must contain the complete accepted setup phase order.",
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
        previousPhaseRoot = hashField(phaseRecord, "phaseRoot", objectPath);
    }
};

const assertCommonBindings = (input: SetupPackageInput): void => {
    assertContext(input.setupContext);
    assertObjectType(input.qShare, "qShare", "QSharePrimeList");
    if (
        deriveProtocolHash("QSharePrimeListHash", input.qShare) !==
        input.setupContext.qShareHash
    ) {
        throw new Error("qShare must match setupContext.qShareHash.");
    }
    assertPhaseTranscript(input.setupContext, input.phaseTranscript);
    assertObjectType(
        input.commonRandomness,
        "commonRandomness",
        "SetupCommonRandomness",
    );
    assertCommonRandomnessContextMatches(
        input.setupContext,
        input.commonRandomness,
        "commonRandomness",
    );
    hashField(
        input.commonRandomness,
        "commonRandomnessRoot",
        "commonRandomness",
    );
    assertObjectType(
        input.vssCoefficientCommitments,
        "vssCoefficientCommitments",
        "VssCoefficientCommitmentSet",
    );
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        "vssCoefficientCommitments",
    );
    hashField(
        input.vssCoefficientCommitments,
        "vssCoefficientCommitmentRoot",
        "vssCoefficientCommitments",
    );
    assertObjectType(
        input.vssCoefficientCommitmentMaterial,
        "vssCoefficientCommitmentMaterial",
        "VssCoefficientCommitmentMaterialSet",
    );
    hashField(
        input.vssCoefficientCommitmentMaterial,
        "vssCoefficientCommitmentMaterialRoot",
        "vssCoefficientCommitmentMaterial",
    );
    assertObjectType(
        input.privateVssEnvelopeCommitments,
        "privateVssEnvelopeCommitments",
        "PrivateVssEnvelopeCommitmentSet",
    );
    hashField(
        input.privateVssEnvelopeCommitments,
        "privateVssEnvelopeCommitmentRoot",
        "privateVssEnvelopeCommitments",
    );
    assertObjectType(
        input.vssShareAcceptances,
        "vssShareAcceptances",
        "VssShareAcceptanceSet",
    );
    assertContextMatches(
        input.setupContext,
        input.vssShareAcceptances,
        "vssShareAcceptances",
    );
    hashField(
        input.vssShareAcceptances,
        "vssShareAcceptanceRoot",
        "vssShareAcceptances",
    );
    if (input.vssComplaints !== undefined) {
        assertObjectType(
            input.vssComplaints,
            "vssComplaints",
            "VssComplaintSet",
        );
        hashField(input.vssComplaints, "vssComplaintRoot", "vssComplaints");
    }
};

const assertKeyRecordBindings = (input: SetupPackageInput): void => {
    assertObjectType(
        input.sameSecretConsistency,
        "sameSecretConsistency",
        "SameSecretConsistencyStatementSet",
    );
    hashField(
        input.sameSecretConsistency,
        "sameSecretConsistencyRoot",
        "sameSecretConsistency",
    );
    assertObjectType(
        input.sameSecretProofs,
        "sameSecretProofs",
        "SameSecretProofSet",
    );
    hashField(
        input.sameSecretProofs,
        "sameSecretProofSetRoot",
        "sameSecretProofs",
    );
    assertObjectType(
        input.publicKeyShares,
        "publicKeyShares",
        "PublicKeyShareSet",
    );
    hashField(
        input.publicKeyShares,
        "publicKeyShareSetRoot",
        "publicKeyShares",
    );
    assertObjectType(
        input.publicKeyShareProofs,
        "publicKeyShareProofs",
        "PublicKeyShareProofSet",
    );
    hashField(
        input.publicKeyShareProofs,
        "publicKeyShareProofSetRoot",
        "publicKeyShareProofs",
    );
    assertObjectType(
        input.publicKeyShareMaterial,
        "publicKeyShareMaterial",
        "PublicKeyShareMaterialSet",
    );
    hashField(
        input.publicKeyShareMaterial,
        "publicKeyShareMaterialSetRoot",
        "publicKeyShareMaterial",
    );
    assertObjectType(
        input.publicKeyShareSuccinctProofs,
        "publicKeyShareSuccinctProofs",
        "PublicKeyShareSuccinctProofSet",
    );
    hashField(
        input.publicKeyShareSuccinctProofs,
        "publicKeyShareSuccinctProofSetRoot",
        "publicKeyShareSuccinctProofs",
    );
    assertObjectType(
        input.evaluatorKeySchedule,
        "evaluatorKeySchedule",
        "EvaluatorKeySchedule",
    );
    hashField(
        input.evaluatorKeySchedule,
        "evaluatorKeyScheduleRoot",
        "evaluatorKeySchedule",
    );
    assertObjectType(
        input.relinearizationKeyShareRounds,
        "relinearizationKeyShareRounds",
        "RelinearizationKeyShareRounds",
    );
    hashField(
        input.relinearizationKeyShareRounds,
        "relinearizationKeyShareRoundsRoot",
        "relinearizationKeyShareRounds",
    );
    for (const [batchIndex, batch] of input.galoisKeyShareBatches.entries()) {
        const objectPath = `galoisKeyShareBatches.${String(batchIndex)}`;
        assertObjectType(batch, objectPath, "GaloisKeyShareBatch");
        hashField(batch, "galoisKeyShareBatchRoot", objectPath);
    }
    assertObjectType(
        input.trusteeEvaluationKeyProofs,
        "trusteeEvaluationKeyProofs",
        "TrusteeEvaluationKeyProofSet",
    );
    hashField(
        input.trusteeEvaluationKeyProofs,
        "trusteeEvaluationKeyProofSetRoot",
        "trusteeEvaluationKeyProofs",
    );
    if (
        input.trusteeEvaluationKeyProofs.relinearizationKeyShareRoundsRoot !==
        input.relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot
    ) {
        throw new Error(
            "trusteeEvaluationKeyProofs must bind the supplied relinearization share-record container.",
        );
    }
    assertObjectType(
        input.evaluationKeys,
        "evaluationKeys",
        "PublicEvaluationKeySet",
    );
    hashField(input.evaluationKeys, "evaluationKeySetHash", "evaluationKeys");
};

const compactVssPublicMaterialFieldNames = [
    "compactVssCoefficientCommitmentSet",
    "compactVssRecipientShareCommitmentSet",
    "compactVssAggregateThresholdCommitmentSet",
    "compactVssShareLinkageStatement",
    "compactVssShareLinkageProofMaterialSet",
] as const satisfies readonly (keyof SetupPackageInput)[];

const compactSameSecretBridgeFieldNames = [
    "compactSameSecretBridgeStatementSet",
    "compactSameSecretBridgeProofMaterialSet",
] as const satisfies readonly (keyof SetupPackageInput)[];

const compactSameSecretBridgeEvidenceFieldNames = [
    "compactSameSecretBridgeStatementSet",
    "compactSameSecretBridgeProofMaterialSet",
    "sameSecretConsistency",
    "sameSecretProofs",
] as const satisfies readonly (keyof SetupPackageInput)[];

const assertCompleteOptionalFieldGroup = <
    FieldName extends keyof SetupPackageInput,
>(
    input: SetupPackageInput,
    fieldNames: readonly FieldName[],
    groupDescription: string,
): void => {
    const presentFieldNames = fieldNames.filter(
        (fieldName) => input[fieldName] !== undefined,
    );
    if (presentFieldNames.length === 0) {
        return;
    }
    const missingFieldNames = fieldNames.filter(
        (fieldName) => input[fieldName] === undefined,
    );
    if (missingFieldNames.length > 0) {
        throw new Error(
            `${groupDescription} requires ${missingFieldNames.join(", ")} when any related field is supplied.`,
        );
    }
};

const assertPublicMatrixSeedMatchesCommonRandomness = (
    commonRandomnessPublicMatrixSeedHash: ProtocolHash,
    publicMatrixSeedHash: unknown,
    objectPath: string,
): void => {
    if (publicMatrixSeedHash !== commonRandomnessPublicMatrixSeedHash) {
        throw new Error(
            `${objectPath}.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash.`,
        );
    }
};

const positiveSafeIntegerField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (!Number.isSafeInteger(fieldValue) || (fieldValue as number) <= 0) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a positive safe integer.`,
        );
    }

    return fieldValue as number;
};

const assertSetupContextNumberMatches = (
    setupContext: CollectiveBgvSetupContext,
    boundValue: Readonly<Record<string, unknown>>,
    boundFieldName: string,
    setupContextFieldName: string,
    objectPath: string,
): void => {
    if (
        positiveSafeIntegerField(boundValue, boundFieldName, objectPath) !==
        positiveSafeIntegerField(
            setupContext,
            setupContextFieldName,
            "setupContext",
        )
    ) {
        throw new Error(
            `${objectPath}.${boundFieldName} must match setupContext.${setupContextFieldName}.`,
        );
    }
};

const assertBoundValueMatches = (
    actual: unknown,
    expected: unknown,
    objectPath: string,
    fieldName: string,
    expectedObjectPath: string,
    expectedFieldName = fieldName,
): void => {
    if (actual !== expected) {
        throw new Error(
            `${objectPath}.${fieldName} must match ${expectedObjectPath}.${expectedFieldName}.`,
        );
    }
};

export const assertRootBoundCertificateHash = (
    certificate: Readonly<Record<string, unknown>>,
    hashFieldName: string,
    hashNamespace: string,
    objectPath: string,
): ProtocolHash => {
    const certificateHash = hashField(certificate, hashFieldName, objectPath);
    const certificateBody = { ...certificate };
    delete certificateBody[hashFieldName];
    if (
        deriveProtocolHash(hashNamespace, certificateBody) !== certificateHash
    ) {
        throw new Error(
            `${objectPath}.${hashFieldName} must match the certificate body.`,
        );
    }

    return certificateHash;
};

export const assertCompactSameSecretBridgeEvidenceFieldGroup = (
    input: Pick<
        SetupPackageInput,
        | "compactSameSecretBridgeStatementSet"
        | "compactSameSecretBridgeProofMaterialSet"
        | "sameSecretConsistency"
        | "sameSecretProofs"
    >,
): void => {
    const presentCompactBridgeFieldNames =
        compactSameSecretBridgeFieldNames.filter(
            (fieldName) => input[fieldName] !== undefined,
        );
    if (presentCompactBridgeFieldNames.length === 0) {
        return;
    }

    const missingFieldNames = compactSameSecretBridgeEvidenceFieldNames.filter(
        (fieldName) => input[fieldName] === undefined,
    );
    if (missingFieldNames.length > 0) {
        throw new Error(
            `compact same-secret bridge material requires ${missingFieldNames.join(", ")} when any compact bridge field is supplied.`,
        );
    }
};

const assertOptionalCompactVssPublicMaterial = (
    input: SetupPackageInput,
): void => {
    assertCompleteOptionalFieldGroup(
        input,
        compactVssPublicMaterialFieldNames,
        "compact VSS public material",
    );
    if (input.compactVssCoefficientCommitmentSet === undefined) {
        return;
    }

    const commonRandomnessPublicMatrixSeedHash = hashField(
        input.commonRandomness,
        "publicMatrixSeedHash",
        "commonRandomness",
    );
    const coefficientCommitmentSet =
        input.compactVssCoefficientCommitmentSet as CompactVssCoefficientCommitmentSet;
    const recipientShareCommitmentSet =
        input.compactVssRecipientShareCommitmentSet as CompactVssRecipientShareCommitmentSet;
    const aggregateThresholdCommitmentSet =
        input.compactVssAggregateThresholdCommitmentSet as CompactVssAggregateThresholdCommitmentSet;
    const statement =
        input.compactVssShareLinkageStatement as CompactVssShareLinkageStatement;
    const proofMaterialSet =
        input.compactVssShareLinkageProofMaterialSet as CompactVssShareLinkageProofMaterialSet;

    assertContextMatches(
        input.setupContext,
        statement,
        "compactVssShareLinkageStatement",
    );
    for (const [objectPath, compactObject] of [
        ["compactVssCoefficientCommitmentSet", coefficientCommitmentSet],
        ["compactVssRecipientShareCommitmentSet", recipientShareCommitmentSet],
        [
            "compactVssAggregateThresholdCommitmentSet",
            aggregateThresholdCommitmentSet,
        ],
        ["compactVssShareLinkageStatement", statement],
    ] as const) {
        assertSetupContextNumberMatches(
            input.setupContext,
            compactObject,
            "participantCount",
            "participantCount",
            objectPath,
        );
    }
    assertSetupContextNumberMatches(
        input.setupContext,
        coefficientCommitmentSet,
        "thresholdDegree",
        "qDec",
        "compactVssCoefficientCommitmentSet",
    );
    assertSetupContextNumberMatches(
        input.setupContext,
        statement,
        "thresholdDegree",
        "qDec",
        "compactVssShareLinkageStatement",
    );
    assertBoundValueMatches(
        statement.coefficientCommitmentRoot,
        coefficientCommitmentSet.coefficientCommitmentRoot,
        "compactVssShareLinkageStatement",
        "coefficientCommitmentRoot",
        "compactVssCoefficientCommitmentSet",
    );
    assertBoundValueMatches(
        statement.recipientShareCommitmentRoot,
        recipientShareCommitmentSet.recipientShareCommitmentRoot,
        "compactVssShareLinkageStatement",
        "recipientShareCommitmentRoot",
        "compactVssRecipientShareCommitmentSet",
    );
    assertBoundValueMatches(
        statement.aggregateThresholdCommitmentRoot,
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
        "compactVssShareLinkageStatement",
        "aggregateThresholdCommitmentRoot",
        "compactVssAggregateThresholdCommitmentSet",
    );

    verifyCompactVssShareLinkageProofMaterialSet({
        coefficientCommitmentSet,
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
        statement,
        proofMaterialSet,
    });
    for (const [objectPath, publicMatrixSeedHash] of [
        [
            "compactVssCoefficientCommitmentSet",
            coefficientCommitmentSet.publicMatrixSeedHash,
        ],
        [
            "compactVssRecipientShareCommitmentSet",
            recipientShareCommitmentSet.publicMatrixSeedHash,
        ],
        [
            "compactVssAggregateThresholdCommitmentSet",
            aggregateThresholdCommitmentSet.publicMatrixSeedHash,
        ],
        ["compactVssShareLinkageStatement", statement.publicMatrixSeedHash],
        [
            "compactVssShareLinkageProofMaterialSet",
            proofMaterialSet.publicMatrixSeedHash,
        ],
    ] as const) {
        assertPublicMatrixSeedMatchesCommonRandomness(
            commonRandomnessPublicMatrixSeedHash,
            publicMatrixSeedHash,
            objectPath,
        );
    }
};

const assertOptionalCompactSameSecretBridge = (
    input: SetupPackageInput,
): void => {
    assertCompactSameSecretBridgeEvidenceFieldGroup(input);
    if (input.compactSameSecretBridgeStatementSet === undefined) {
        return;
    }

    const commonRandomnessPublicMatrixSeedHash = hashField(
        input.commonRandomness,
        "publicMatrixSeedHash",
        "commonRandomness",
    );
    const statementSet =
        input.compactSameSecretBridgeStatementSet as CompactVssSameSecretBridgeStatementSet;
    const proofMaterialSet =
        input.compactSameSecretBridgeProofMaterialSet as CompactVssSameSecretBridgeProofMaterialSet;
    if (input.compactVssCoefficientCommitmentSet === undefined) {
        throw new Error(
            "compact same-secret bridge material requires compactVssCoefficientCommitmentSet.",
        );
    }
    const coefficientCommitmentSet =
        input.compactVssCoefficientCommitmentSet as CompactVssCoefficientCommitmentSet;

    assertContextMatches(
        input.setupContext,
        statementSet,
        "compactSameSecretBridgeStatementSet",
    );
    assertSetupContextNumberMatches(
        input.setupContext,
        statementSet,
        "participantCount",
        "participantCount",
        "compactSameSecretBridgeStatementSet",
    );
    assertSetupContextNumberMatches(
        input.setupContext,
        statementSet,
        "thresholdDegree",
        "qDec",
        "compactSameSecretBridgeStatementSet",
    );
    assertBoundValueMatches(
        statementSet.compactCoefficientCommitmentRoot,
        coefficientCommitmentSet.coefficientCommitmentRoot,
        "compactSameSecretBridgeStatementSet",
        "compactCoefficientCommitmentRoot",
        "compactVssCoefficientCommitmentSet",
        "coefficientCommitmentRoot",
    );
    assertBoundValueMatches(
        statementSet.sameSecretConsistencyRoot,
        input.sameSecretConsistency.sameSecretConsistencyRoot,
        "compactSameSecretBridgeStatementSet",
        "sameSecretConsistencyRoot",
        "sameSecretConsistency",
    );
    assertBoundValueMatches(
        statementSet.sameSecretProofSetRoot,
        (input.sameSecretProofs as SameSecretProofSet).sameSecretProofSetRoot,
        "compactSameSecretBridgeStatementSet",
        "sameSecretProofSetRoot",
        "sameSecretProofs",
    );

    verifyCompactVssSameSecretBridgeProofMaterialSet({
        statementSet,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs as SameSecretProofSet,
        transportedSameSecretProofMaterial:
            input.transportedSameSecretProofMaterial as
                | TransportedSameSecretProofMaterialSet
                | undefined,
        proofMaterialSet,
    });
    assertPublicMatrixSeedMatchesCommonRandomness(
        commonRandomnessPublicMatrixSeedHash,
        statementSet.publicMatrixSeedHash,
        "compactSameSecretBridgeStatementSet",
    );
    assertPublicMatrixSeedMatchesCommonRandomness(
        commonRandomnessPublicMatrixSeedHash,
        proofMaterialSet.publicMatrixSeedHash,
        "compactSameSecretBridgeProofMaterialSet",
    );
};

const assertCommonRandomnessPublicDerivationsBindPackageInput = (
    input: SetupPackageInput,
): void => {
    const publicMatrixSeedHash = hashField(
        input.commonRandomness,
        "publicMatrixSeedHash",
        "commonRandomness",
    );
    const publicDerivations = assertObjectRecord(
        input.commonRandomness.publicDerivations,
        "commonRandomness.publicDerivations",
    );
    if (
        publicDerivations.objectType !== "SetupPublicDerivations" ||
        publicDerivations.objectVersion !== 1 ||
        publicDerivations.setupProfileId !== setupProfileId ||
        publicDerivations.publicMatrixSeedHash !== publicMatrixSeedHash
    ) {
        throw new Error(
            "commonRandomness.publicDerivations must match the accepted setup public derivation profile.",
        );
    }

    const crpRoots = assertObjectRecord(
        publicDerivations.crpRoots,
        "commonRandomness.publicDerivations.crpRoots",
    );
    const bgvPublicA = assertObjectRecord(
        publicDerivations.bgvPublicA,
        "commonRandomness.publicDerivations.bgvPublicA",
    );
    const publicKeyShareMaterial = assertObjectRecord(
        input.publicKeyShareMaterial,
        "publicKeyShareMaterial",
    );
    if (publicKeyShareMaterial.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            "publicKeyShareMaterial.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash.",
        );
    }
    if (publicKeyShareMaterial.publicKeyCrpRoot !== crpRoots.publicKeyCrpRoot) {
        throw new Error(
            "publicKeyShareMaterial.publicKeyCrpRoot must match commonRandomness public derivations.",
        );
    }
    if (
        publicKeyShareMaterial.publicAPolynomialRoot !==
        bgvPublicA.publicPolynomialRoot
    ) {
        throw new Error(
            "publicKeyShareMaterial.publicAPolynomialRoot must match commonRandomness public derivations.",
        );
    }

    const evaluatorKeySchedule = assertObjectRecord(
        input.evaluatorKeySchedule,
        "evaluatorKeySchedule",
    );
    if (evaluatorKeySchedule.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            "evaluatorKeySchedule.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash.",
        );
    }
    if (
        evaluatorKeySchedule.relinearizationCrpRoot !==
        crpRoots.relinearizationCrpRoot
    ) {
        throw new Error(
            "evaluatorKeySchedule.relinearizationCrpRoot must match commonRandomness public derivations.",
        );
    }
    if (evaluatorKeySchedule.galoisKeyCrpRoot !== crpRoots.galoisKeyCrpRoot) {
        throw new Error(
            "evaluatorKeySchedule.galoisKeyCrpRoot must match commonRandomness public derivations.",
        );
    }
};

export const resolveThresholdShareCommitments = (
    input: SetupPackageInput,
): ThresholdShareCommitmentSet => {
    const materialEncoding = (
        input.vssCoefficientCommitmentMaterial as Readonly<
            Record<string, unknown>
        >
    ).materialEncoding;
    if (
        materialEncoding ===
            "binary-chunked-full-public-setup-commitment-values" &&
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
            "thresholdShareCommitments must match the verifier-derived commitments from VSS coefficient material.",
        );
    }

    return derivedThresholdShareCommitments;
};

const assertCertificateBindings = (
    certificates: SetupPackageCertificateRecords,
): void => {
    assertObjectType(
        certificates.setupCommitmentSecurityCertificate,
        "setupCommitmentSecurityCertificate",
        "SetupCommitmentSecurityCertificate",
    );
    assertRootBoundCertificateHash(
        certificates.setupCommitmentSecurityCertificate,
        "setupCommitmentSecurityCertificateHash",
        "SetupCommitmentSecurityCertificateHash",
        "setupCommitmentSecurityCertificate",
    );
    assertObjectType(
        certificates.setupTransportCertificate,
        "setupTransportCertificate",
        "SetupTransportCertificate",
    );
    assertRootBoundCertificateHash(
        certificates.setupTransportCertificate,
        "setupTransportCertificateHash",
        "SetupTransportCertificateHash",
        "setupTransportCertificate",
    );
    assertObjectType(
        certificates.setupProofAccountingCertificate,
        "setupProofAccountingCertificate",
        "SetupProofAccountingCertificate",
    );
    assertRootBoundCertificateHash(
        certificates.setupProofAccountingCertificate,
        "setupProofAccountingCertificateHash",
        "SetupProofAccountingCertificateHash",
        "setupProofAccountingCertificate",
    );
    assertObjectType(
        certificates.heSecurityCertificate,
        "heSecurityCertificate",
        "BgvHeSecurityCertificate",
    );
    assertRootBoundCertificateHash(
        certificates.heSecurityCertificate,
        "heSecurityCertificateHash",
        "BGVHeSecurityCertificateHash",
        "heSecurityCertificate",
    );
};

const assertGaloisScheduleCovered = (input: SetupPackageInput): void => {
    const requiredGaloisKeySchedule =
        input.evaluatorKeySchedule.requiredGaloisKeySchedule;
    if (!Array.isArray(requiredGaloisKeySchedule)) {
        throw new TypeError(
            "evaluatorKeySchedule.requiredGaloisKeySchedule must be an array.",
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

export const validateInput = (
    input: SetupPackageInput,
    certificates: SetupPackageCertificateRecords,
    thresholdShareCommitments: ThresholdShareCommitmentSet,
): void => {
    assertCommonBindings(input);
    assertObjectType(
        thresholdShareCommitments,
        "thresholdShareCommitments",
        "ThresholdShareCommitmentSet",
    );
    hashField(
        thresholdShareCommitments,
        "thresholdShareCommitmentRoot",
        "thresholdShareCommitments",
    );
    assertKeyRecordBindings(input);
    assertCommonRandomnessPublicDerivationsBindPackageInput(input);
    assertOptionalCompactVssPublicMaterial(input);
    assertOptionalCompactSameSecretBridge(input);
    assertCertificateBindings(certificates);
    assertGaloisScheduleCovered(input);
};
