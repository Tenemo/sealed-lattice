export type RequiredRustHeavyEvidenceTest = {
    readonly claimEvidence: string;
    readonly relativePath: string;
    readonly testName: string;
};

export const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

const evaluationKeyShareProofsPath =
    'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/evaluation_key_share_proofs.rs';
const publicKeyShareProofsPath =
    'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/public_key_share_proofs.rs';
const sameSecretProofsPath =
    'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/same_secret_proofs.rs';
const setupCertificatesPath =
    'crates/sealed-lattice-kernel/src/bgv/setup/tests/accepted_setup/setup_certificates.rs';

export const requiredRustHeavyEvidenceTests = [
    {
        claimEvidence:
            'transported same-secret proof material is consumed by the terminal public setup verifier',
        relativePath: sameSecretProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_from_transported_proof_material',
    },
    {
        claimEvidence:
            'transported public-key share material is consumed by the terminal public setup verifier',
        relativePath: publicKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_material_from_transport',
    },
    {
        claimEvidence:
            'transported public-key share proof material is consumed by the terminal public setup verifier',
        relativePath: publicKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_succinct_proofs_from_transported_proof_material',
    },
    {
        claimEvidence:
            'transported trustee evaluation-key proof material is consumed by the terminal public setup verifier',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_checks_trustee_proofs_from_transported_proof_material',
    },
    {
        claimEvidence:
            'transported public evaluation-key material is consumed by the terminal public setup verifier',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material',
    },
    {
        claimEvidence:
            'setup transport refuses tampered same-secret proof chunks',
        relativePath: sameSecretProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_same_secret_proof_chunk',
    },
    {
        claimEvidence:
            'setup transport refuses tampered public-key share proof chunks',
        relativePath: publicKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_succinct_proof_chunk',
    },
    {
        claimEvidence:
            'setup transport refuses tampered public-key share material',
        relativePath: publicKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_material',
    },
    {
        claimEvidence:
            'setup transport refuses tampered trustee evaluation-key proof chunks',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_trustee_proof_chunk',
    },
    {
        claimEvidence:
            'setup transport refuses tampered public evaluation-key material chunks',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk',
    },
    {
        claimEvidence:
            'setup verifier recomputes and refuses setup proof-accounting certificate hash drift',
        relativePath: setupCertificatesPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_accounting_certificate_hash_drift',
    },
    {
        claimEvidence:
            'setup verifier recomputes and refuses setup key-correctness certificate hash drift',
        relativePath: setupCertificatesPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_certificate_hash_drift',
    },
    {
        claimEvidence:
            'setup verifier refuses evaluation-key aggregate source drift',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift',
    },
    {
        claimEvidence:
            'setup verifier refuses trustee-specific key-switch seed drift',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed',
    },
    {
        claimEvidence: 'setup verifier refuses evaluation-key schedule drift',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift',
    },
    {
        claimEvidence: 'setup verifier refuses public-key aggregate drift',
        relativePath: publicKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate',
    },
    {
        claimEvidence:
            'setup verifier refuses same-secret proof-family rebinding',
        relativePath: sameSecretProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_rebinding',
    },
    {
        claimEvidence:
            'setup verifier refuses every recomputed accepted root drift over the terminal public package graph',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_refuses_every_recomputed_accepted_root_drift',
    },
    {
        claimEvidence:
            'setup verifier refuses terminal trustee proof statement-hash drift after dependent roots are rebound',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_collective_setup_verifier_refuses_terminal_trustee_proof_statement_hash_drift',
    },
    {
        claimEvidence:
            'setup-output integration evidence from accepted setup verifier output into direct ballot package creation, verification, and aggregation',
        relativePath: evaluationKeyShareProofsPath,
        testName:
            'heavy_accepted_setup_output_drives_direct_encrypted_ballot_package_flow',
    },
] as const satisfies readonly RequiredRustHeavyEvidenceTest[];
