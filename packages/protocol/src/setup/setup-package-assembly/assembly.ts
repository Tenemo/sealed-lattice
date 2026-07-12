import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { resolveThresholdShareCommitments, validateInput } from './bindings.js';
import {
    derivedCollectivePublicKey,
    resolveSetupCertificateRecords,
} from './certificates.js';
import { hashField } from './constants-and-assertions.js';
import { vssCoefficientCommitmentMaterialReferenceFromCertificate } from './transported-material.js';
import type { SetupPackage, SetupPackageInput } from './types.js';
import {
    publicPrivateVssEnvelopeCommitmentSet,
    setupPackageHashInput,
} from './verification-input.js';

export const createSetupPackage = async (
    input: SetupPackageInput,
): Promise<SetupPackage> => {
    const certificates = resolveSetupCertificateRecords(input);
    const thresholdShareCommitments = resolveThresholdShareCommitments(input);
    validateInput(input, certificates, thresholdShareCommitments);
    const collectivePublicKey = await derivedCollectivePublicKey(input);
    const vssCoefficientCommitmentMaterial =
        vssCoefficientCommitmentMaterialReferenceFromCertificate(
            input,
            certificates.setupTransportCertificate,
        );

    const privateVssEnvelopeCommitments = publicPrivateVssEnvelopeCommitmentSet(
        input.privateVssEnvelopeCommitments,
    );
    const setupTransportCertificateHash = hashField(
        certificates.setupTransportCertificate,
        'setupTransportCertificateHash',
        'setupTransportCertificate',
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
        setupContext: input.setupContext,
        qShare: input.qShare,
        phaseTranscript: input.phaseTranscript,
        commonRandomness: input.commonRandomness,
        vssCoefficientCommitments: input.vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial,
        vssPublicCoefficientCommitmentSet:
            input.vssPublicCoefficientCommitmentSet,
        vssPublicRecipientShareCommitmentSet:
            input.vssPublicRecipientShareCommitmentSet,
        vssPublicAggregateThresholdCommitmentSet:
            input.vssPublicAggregateThresholdCommitmentSet,
        vssShareLinkageStatement: input.vssShareLinkageStatement,
        vssShareLinkageProofMaterialSet: input.vssShareLinkageProofMaterialSet,
        privateVssEnvelopeCommitments,
        privateVssEnvelopeCommitmentRoot,
        ...(input.vssComplaints === undefined
            ? {}
            : { vssComplaints: input.vssComplaints }),
        vssShareAcceptances: input.vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretBridgeStatementSet: input.sameSecretBridgeStatementSet,
        sameSecretBridgeProofMaterialSet:
            input.sameSecretBridgeProofMaterialSet,
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
        setupTransportCertificate: certificates.setupTransportCertificate,
        setupTransportCertificateHash,
    } as const satisfies Omit<SetupPackage, 'setupPackageHash'>;

    return {
        ...packageWithoutHash,
        setupPackageHash: deriveCanonicalObjectHash(
            setupPackageHashInput(packageWithoutHash),
        ),
    } satisfies SetupPackage;
};
