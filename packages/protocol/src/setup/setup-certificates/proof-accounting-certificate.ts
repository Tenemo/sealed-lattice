import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupProofByteDecoder,
    setupProofBytesDomain,
    setupProofFamilies,
    setupProofSerialization,
} from './constants.js';
import {
    acceptedCertificateTemplate,
    hashField,
    objectField,
} from './field-helpers.js';
import type {
    CollectiveBgvSetupParametersForCertificates,
    JsonRecord,
    SetupProofAccountingCertificate,
    SetupProofAccountingCertificateBody,
} from './types.js';

const setupProofRecordBindingForCertificate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
): JsonRecord => {
    const setupProofParameters = setupParameters.setupProof;

    return {
        objectType: 'SetupProofRecordBinding',
        objectVersion: 1,
        setupParametersHash: setupParameters.setupParametersHash,
        proofBytesDomain: setupProofBytesDomain,
        proofSerialization: setupProofSerialization,
        proofByteDecoder: setupProofByteDecoder,
        privateVssShareProofAccountingHash: hashField(
            setupProofParameters,
            'privateVssShareProofAccountingHash',
            'setupParameters.setupProof',
        ),
    };
};

const setupProofFamilyAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord[] => [
    {
        proofFamily: 'vss-opening-carry',
        claimAccounting: {
            accountingHash: privateVssShareProofAccountingHash,
        },
    },
    {
        proofFamily: 'same-secret-linkage-anchor',
        claimAccounting: {
            accountingHash: sameSecretLinkageAnchorProofAccountingHash,
        },
    },
    {
        proofFamily: 'public-key-share',
        claimAccounting: {
            accountingHash: publicKeyShareProofAccountingHash,
        },
    },
    {
        proofFamily: 'trustee-evaluation-key',
        claimAccounting: {
            accountingHash: trusteeEvaluationKeyProofAccountingHash,
        },
    },
];

const setupProofSuccinctTransportAccounting = (): JsonRecord => ({
    objectType: 'SetupProofSuccinctTransportAccounting',
    objectVersion: 1,
});

const setupProofSuccinctLeakageAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord => ({
    objectType: 'SetupProofSuccinctLeakageAccounting',
    objectVersion: 1,
    familyAccountingHashes: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShare: publicKeyShareProofAccountingHash,
        privateVssShare: privateVssShareProofAccountingHash,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccountingHash,
    },
});

const setupProofFiatShamirTranscriptAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord => ({
    objectType: 'SetupProofFiatShamirTranscriptAccounting',
    objectVersion: 1,
    familyAccountingHashes: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShare: publicKeyShareProofAccountingHash,
        privateVssShare: privateVssShareProofAccountingHash,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccountingHash,
    },
    challengeBinding:
        'each succinct proof statement hash, proof family label, binding roots, Merkle transcript, low-degree transcript, and challenge-extension sampling rule is recorded inside the bound family accounting object',
});

const setupProofTheoremAccounting = (
    privateVssShareProofAccounting: JsonRecord,
    sameSecretLinkageAnchorProofAccounting: JsonRecord,
    publicKeyShareProofAccounting: JsonRecord,
    trusteeEvaluationKeyProofAccounting: JsonRecord,
): JsonRecord => ({
    objectType: 'SetupProofTheoremAccounting',
    objectVersion: 1,
    proofFamilies: [
        'same-secret-linkage-anchor',
        'public-key-share',
        'vss-opening-carry',
        'trustee-evaluation-key',
    ],
    familyAccounting: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccounting,
        publicKeyShare: publicKeyShareProofAccounting,
        privateVssShare: privateVssShareProofAccounting,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccounting,
    },
});

const setupProofAccountingCertificateBody = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord,
    publicKeyShareProofAccounting: JsonRecord,
    trusteeEvaluationKeyProofAccounting: JsonRecord,
): SetupProofAccountingCertificateBody => {
    const setupProofParameters = setupParameters.setupProof;
    const setupProofRecordBinding =
        setupProofRecordBindingForCertificate(setupParameters);
    const sameSecretLinkageAnchorProofAccountingHash =
        deriveCanonicalObjectHash(sameSecretLinkageAnchorProofAccounting);
    const privateVssShareProofAccounting = objectField(
        setupProofParameters,
        'privateVssShareProofAccounting',
        'setupParameters.setupProof',
    );
    const privateVssShareProofAccountingHash = deriveCanonicalObjectHash(
        privateVssShareProofAccounting,
    );
    const expectedPrivateVssShareProofAccountingHash = hashField(
        setupProofParameters,
        'privateVssShareProofAccountingHash',
        'setupParameters.setupProof',
    );
    if (
        privateVssShareProofAccountingHash !==
        expectedPrivateVssShareProofAccountingHash
    ) {
        throw new Error(
            'setupParameters.setupProof.privateVssShareProofAccountingHash must match privateVssShareProofAccounting.',
        );
    }
    const publicKeyShareProofAccountingHash = deriveCanonicalObjectHash(
        publicKeyShareProofAccounting,
    );
    const trusteeEvaluationKeyProofAccountingHash = deriveCanonicalObjectHash(
        trusteeEvaluationKeyProofAccounting,
    );

    return {
        objectType: 'SetupProofAccountingCertificate',
        objectVersion: 1,
        setupParametersHash: setupParameters.setupParametersHash,
        setupProofRecordBinding,
        setupProofRecordBindingHash: deriveCanonicalObjectHash(
            setupProofRecordBinding,
        ),
        proofFamilies: setupProofFamilies,
        proofFamilyAccounting: setupProofFamilyAccounting(
            privateVssShareProofAccountingHash,
            sameSecretLinkageAnchorProofAccountingHash,
            publicKeyShareProofAccountingHash,
            trusteeEvaluationKeyProofAccountingHash,
        ),
        sameSecretLinkageAnchorProofAccounting,
        sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShareProofAccounting,
        publicKeyShareProofAccountingHash,
        trusteeEvaluationKeyProofAccounting,
        trusteeEvaluationKeyProofAccountingHash,
        succinctTransportAccounting: setupProofSuccinctTransportAccounting(),
        succinctLeakageAccounting: setupProofSuccinctLeakageAccounting(
            privateVssShareProofAccountingHash,
            sameSecretLinkageAnchorProofAccountingHash,
            publicKeyShareProofAccountingHash,
            trusteeEvaluationKeyProofAccountingHash,
        ),
        fiatShamirTranscriptAccounting:
            setupProofFiatShamirTranscriptAccounting(
                privateVssShareProofAccountingHash,
                sameSecretLinkageAnchorProofAccountingHash,
                publicKeyShareProofAccountingHash,
                trusteeEvaluationKeyProofAccountingHash,
            ),
        proofTheoremAccounting: setupProofTheoremAccounting(
            privateVssShareProofAccounting,
            sameSecretLinkageAnchorProofAccounting,
            publicKeyShareProofAccounting,
            trusteeEvaluationKeyProofAccounting,
        ),
    };
};

export const createSetupProofAccountingCertificate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord | undefined,
    publicKeyShareProofAccounting: JsonRecord | undefined,
    trusteeEvaluationKeyProofAccounting: JsonRecord | undefined,
): SetupProofAccountingCertificate => {
    const template = acceptedCertificateTemplate(
        setupParameters,
        'setupProofAccountingCertificate',
        'SetupProofAccountingCertificate',
        'setupProofAccountingCertificateHash',
    );
    if (template !== null) {
        return template as SetupProofAccountingCertificate;
    }
    if (sameSecretLinkageAnchorProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires sameSecretLinkageAnchorProofAccounting when no accepted certificate template is supplied.',
        );
    }
    if (trusteeEvaluationKeyProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires trusteeEvaluationKeyProofAccounting when no accepted certificate template is supplied.',
        );
    }
    if (publicKeyShareProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires publicKeyShareProofAccounting when no accepted certificate template is supplied.',
        );
    }

    const certificateBody = setupProofAccountingCertificateBody(
        setupParameters,
        sameSecretLinkageAnchorProofAccounting,
        publicKeyShareProofAccounting,
        trusteeEvaluationKeyProofAccounting,
    );

    return {
        ...certificateBody,
        setupProofAccountingCertificateHash:
            deriveCanonicalObjectHash(certificateBody),
    };
};
