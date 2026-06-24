import { canonicalJson, deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { RequiredGaloisKeyScheduleEntry } from '../evaluator-key-schedule.js';
import type { SetupPhaseRecord } from '../setup-phase-records.js';
import {
    deriveThresholdShareCommitments,
    type ThresholdShareCommitmentSet,
} from '../threshold-share-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    assertCommonRandomnessContextMatches,
    assertContext,
    assertContextMatches,
    assertObjectRecord,
    assertObjectType,
    hashField,
    requiredSetupPhases,
} from './constants-and-assertions.js';
import type {
    SetupPackageCertificateRecords,
    SetupPackageInput,
} from './types.js';

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
        publicDerivations.publicMatrixSeedHash !== publicMatrixSeedHash
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

export const validateInput = (
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
