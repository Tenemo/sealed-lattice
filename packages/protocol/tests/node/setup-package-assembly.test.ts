import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    assertCompactSameSecretBridgeEvidenceFieldGroup,
    assertRootBoundCertificateHash,
} from '#packages/protocol/src/setup/setup-package-assembly/bindings';
import type { SetupPackageInput } from '#packages/protocol/src/setup/setup-package-assembly/types';

type CompactSameSecretBridgeEvidenceFields = Pick<
    SetupPackageInput,
    | 'compactSameSecretBridgeStatementSet'
    | 'compactSameSecretBridgeProofMaterialSet'
    | 'sameSecretConsistency'
    | 'sameSecretProofs'
>;

const placeholderRecord = Object.freeze({
    objectType: 'SetupPackageAssemblyTestRecord',
});

const assertCompactSameSecretBridgeEvidenceGroup = (
    evidenceFields: Partial<
        Record<keyof CompactSameSecretBridgeEvidenceFields, unknown>
    >,
): void => {
    assertCompactSameSecretBridgeEvidenceFieldGroup(
        evidenceFields as CompactSameSecretBridgeEvidenceFields,
    );
};

describe('setup package assembly', () => {
    it('does not activate compact bridge material from ordinary same-secret fields', () => {
        expect(() =>
            assertCompactSameSecretBridgeEvidenceGroup({
                sameSecretConsistency: placeholderRecord,
                sameSecretProofs: placeholderRecord,
            }),
        ).not.toThrow();
    });

    it('requires the complete compact bridge evidence group when proof material is supplied', () => {
        expect(() =>
            assertCompactSameSecretBridgeEvidenceGroup({
                compactSameSecretBridgeProofMaterialSet: placeholderRecord,
            }),
        ).toThrow(
            /compactSameSecretBridgeStatementSet.*sameSecretConsistency.*sameSecretProofs/,
        );
    });

    it('requires ordinary same-secret evidence when compact bridge statements are supplied', () => {
        expect(() =>
            assertCompactSameSecretBridgeEvidenceGroup({
                compactSameSecretBridgeStatementSet: placeholderRecord,
                compactSameSecretBridgeProofMaterialSet: placeholderRecord,
            }),
        ).toThrow(/sameSecretConsistency.*sameSecretProofs/);
    });

    it('accepts a complete compact bridge evidence group for downstream verification', () => {
        expect(() =>
            assertCompactSameSecretBridgeEvidenceGroup({
                compactSameSecretBridgeStatementSet: placeholderRecord,
                compactSameSecretBridgeProofMaterialSet: placeholderRecord,
                sameSecretConsistency: placeholderRecord,
                sameSecretProofs: placeholderRecord,
            }),
        ).not.toThrow();
    });

    it('accepts a setup certificate hash derived from its body', () => {
        const certificateBody = {
            objectType: 'SetupCommitmentSecurityCertificate',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            compactVssParameterCertificateInputBindingHash: '1'.repeat(128),
        };
        const certificateHash = deriveProtocolHash(
            'SetupCommitmentSecurityCertificateHash',
            certificateBody,
        );

        expect(
            assertRootBoundCertificateHash(
                {
                    ...certificateBody,
                    setupCommitmentSecurityCertificateHash: certificateHash,
                },
                'setupCommitmentSecurityCertificateHash',
                'SetupCommitmentSecurityCertificateHash',
                'setupCommitmentSecurityCertificate',
            ),
        ).toBe(certificateHash);
    });

    it('rejects a setup certificate hash after body drift', () => {
        const certificateBody = {
            objectType: 'SetupCommitmentSecurityCertificate',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            compactVssParameterCertificateInputBindingHash: '1'.repeat(128),
        };
        const certificateHash = deriveProtocolHash(
            'SetupCommitmentSecurityCertificateHash',
            certificateBody,
        );

        expect(() =>
            assertRootBoundCertificateHash(
                {
                    ...certificateBody,
                    compactVssParameterCertificateInputBindingHash: '2'.repeat(
                        128,
                    ),
                    setupCommitmentSecurityCertificateHash: certificateHash,
                },
                'setupCommitmentSecurityCertificateHash',
                'SetupCommitmentSecurityCertificateHash',
                'setupCommitmentSecurityCertificate',
            ),
        ).toThrow(/must match the certificate body/);
    });
});
