import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { resolveThresholdShareCommitments, validateInput } from './bindings.js';
import {
    derivedCollectivePublicKey,
    resolveSetupCertificateRecords,
} from './certificates.js';
import { hashField } from './constants-and-assertions.js';
import type { SetupPackage, SetupPackageInput } from './types.js';
import {
    publicPrivateVssEnvelopeCommitmentSet,
    setupPackageHashInput,
} from './verification-input.js';

export const createSetupPackage = (input: SetupPackageInput): SetupPackage => {
    const certificates = resolveSetupCertificateRecords(input);
    const thresholdShareCommitments = resolveThresholdShareCommitments(input);
    validateInput(input, certificates, thresholdShareCommitments);
    const collectivePublicKey = derivedCollectivePublicKey(input);

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
