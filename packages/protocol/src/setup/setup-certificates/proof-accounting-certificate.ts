import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupProofByteDecoder,
    setupProofBytesDomain,
    setupProofFamilies,
    setupProofSerialization,
    succinctEvaluationKeyProofAccountingHashNamespace,
    succinctPrivateVssShareAccountingHashNamespace,
    succinctPublicKeyShareAccountingHashNamespace,
    succinctSameSecretLinkageAnchorAccountingHashNamespace,
} from './constants.js';
import {
    acceptedCertificateTemplate,
    hashField,
    objectField,
} from './field-helpers.js';
import type {
    CollectiveBgvSetupProfileForCertificates,
    JsonRecord,
    SetupProofAccountingCertificate,
    SetupProofAccountingCertificateBody,
} from './types.js';

const setupProofRecordBindingForCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): JsonRecord => {
    const setupProofProfile = setupProfile.setupProofProfile;

    return {
        objectType: 'SetupProofRecordBinding',
        objectVersion: 1,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        proofBytesDomain: setupProofBytesDomain,
        proofSerialization: setupProofSerialization,
        proofByteDecoder: setupProofByteDecoder,
        privateVssShareProofAccountingHash: hashField(
            setupProofProfile,
            'privateVssShareProofAccountingHash',
            'setupProfile.setupProofProfile',
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
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord,
    publicKeyShareProofAccounting: JsonRecord,
    trusteeEvaluationKeyProofAccounting: JsonRecord,
): SetupProofAccountingCertificateBody => {
    const setupProofProfile = setupProfile.setupProofProfile;
    const setupProofRecordBinding =
        setupProofRecordBindingForCertificate(setupProfile);
    const sameSecretLinkageAnchorProofAccountingHash = deriveProtocolHash(
        succinctSameSecretLinkageAnchorAccountingHashNamespace,
        sameSecretLinkageAnchorProofAccounting,
    );
    const privateVssShareProofAccounting = objectField(
        setupProofProfile,
        'privateVssShareProofAccounting',
        'setupProfile.setupProofProfile',
    );
    const privateVssShareProofAccountingHash = deriveProtocolHash(
        succinctPrivateVssShareAccountingHashNamespace,
        privateVssShareProofAccounting,
    );
    const expectedPrivateVssShareProofAccountingHash = hashField(
        setupProofProfile,
        'privateVssShareProofAccountingHash',
        'setupProfile.setupProofProfile',
    );
    if (
        privateVssShareProofAccountingHash !==
        expectedPrivateVssShareProofAccountingHash
    ) {
        throw new Error(
            'setupProfile.setupProofProfile.privateVssShareProofAccountingHash must match privateVssShareProofAccounting.',
        );
    }
    const publicKeyShareProofAccountingHash = deriveProtocolHash(
        succinctPublicKeyShareAccountingHashNamespace,
        publicKeyShareProofAccounting,
    );
    const trusteeEvaluationKeyProofAccountingHash = deriveProtocolHash(
        succinctEvaluationKeyProofAccountingHashNamespace,
        trusteeEvaluationKeyProofAccounting,
    );

    return {
        objectType: 'SetupProofAccountingCertificate',
        objectVersion: 1,
        setupProfileHash: setupProfile.setupProfileHash,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        setupProofRecordBinding,
        setupProofRecordBindingHash: deriveProtocolHash(
            'SetupProofRecordBindingHash',
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
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord | undefined,
    publicKeyShareProofAccounting: JsonRecord | undefined,
    trusteeEvaluationKeyProofAccounting: JsonRecord | undefined,
): SetupProofAccountingCertificate => {
    const template = acceptedCertificateTemplate(
        setupProfile,
        'setupProofAccountingCertificate',
        'SetupProofAccountingCertificate',
        'setupProofAccountingCertificateHash',
        'SetupProofAccountingCertificateHash',
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
        setupProfile,
        sameSecretLinkageAnchorProofAccounting,
        publicKeyShareProofAccounting,
        trusteeEvaluationKeyProofAccounting,
    );

    return {
        ...certificateBody,
        setupProofAccountingCertificateHash: deriveProtocolHash(
            'SetupProofAccountingCertificateHash',
            certificateBody,
        ),
    };
};
