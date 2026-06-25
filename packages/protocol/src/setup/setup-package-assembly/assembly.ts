import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { resolveThresholdShareCommitments, validateInput } from './bindings.js';
import {
    createActiveStaticSetupTheoremCertificate,
    createSetupKeyCorrectnessCertificate,
    derivedCollectivePublicKey,
    resolveSetupCertificateRecords,
} from './certificates.js';
import { hashField } from './constants-and-assertions.js';
import type {
    SetupPackage,
    SetupPackageInput,
    SetupPackageInputWithDerivedCollectivePublicKey,
} from './types.js';
import {
    publicPrivateVssEnvelopeCommitmentSet,
    setupPackageHashInput,
} from './verification-input.js';

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
        setupPackageHash: deriveCanonicalObjectHash(
            setupPackageHashInput(packageWithoutHash),
        ),
    } satisfies SetupPackage;
};
