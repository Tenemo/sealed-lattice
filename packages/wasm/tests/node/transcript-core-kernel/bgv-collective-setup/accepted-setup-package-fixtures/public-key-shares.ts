import { validHash } from '../../bgv-passive-setup-fixtures.js';
import {
    coefficientVectorLittleEndianHex,
    firstProfileParticipantCount,
    hexToBytes,
    jsonRecord,
    minimumSuccinctProofFixtureRingDegree,
    publicKeyShareCoefficientVectorHash,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { hash512Hex } from '#packages/crypto/src/index';
import {
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    publicKeyShareProofFamily,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofSet,
} from '#packages/protocol/src/setup/public-key-share-records';
import {
    setupProofProfileId,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type { BgvCollectiveSetupProfileDescription } from '#packages/wasm/src/index';

const publicKeyShareCoefficients = (
    trusteeRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from(
        { length: minimumSuccinctProofFixtureRingDegree },
        (_unusedCoefficient, coefficientIndex) => {
            const value =
                (trusteeRosterPosition + 1) * 101 +
                (rnsLimbIndex + 1) * 29 +
                coefficientIndex * 13;

            return value % rnsPrime;
        },
    );

const acceptedPublicKeyShareMaterialContributions = (
    profile: BgvCollectiveSetupProfileDescription,
): PublicKeyShareMaterialContributionInput[] =>
    Array.from(
        { length: firstProfileParticipantCount },
        (_unusedTrustee, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
            shareCoefficientVectorsByLimb: profile.qShare.primes.map(
                (rnsPrime, rnsLimbIndex) => {
                    const coefficients = publicKeyShareCoefficients(
                        trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    );

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength:
                            minimumSuccinctProofFixtureRingDegree * 8,
                        coefficientVectorHash512:
                            publicKeyShareCoefficientVectorHash(coefficients),
                        coefficientsLeHex:
                            coefficientVectorLittleEndianHex(coefficients),
                    };
                },
            ),
        }),
    );

const publicKeyShareContributionsFromMaterial = (
    materialContributions: readonly PublicKeyShareMaterialContributionInput[],
): PublicKeyShareContributionInput[] =>
    materialContributions.map((materialContribution) => ({
        trusteeIdentity: materialContribution.trusteeIdentity,
        trusteeRosterPosition: materialContribution.trusteeRosterPosition,
        shareCoefficientVectorHash512ByLimb:
            materialContribution.shareCoefficientVectorsByLimb.map(
                (coefficientVector) => ({
                    rnsLimbIndex: coefficientVector.rnsLimbIndex,
                    rnsPrime: coefficientVector.rnsPrime,
                    component: coefficientVector.component,
                    coefficientVectorHash512:
                        coefficientVector.coefficientVectorHash512,
                }),
            ),
    }));

export function acceptedPublicKeyShares(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
): PublicKeyShareSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const publicKeyCrpRoot = String(crpRoots.publicKeyCrpRoot);
    const publicAPolynomialRoot = String(publicA.publicPolynomialRoot);

    return createPublicKeyShareSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        shareContributions: publicKeyShareContributionsFromMaterial(
            acceptedPublicKeyShareMaterialContributions(profile),
        ),
    });
}

export function acceptedPublicKeyShareMaterial(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    publicKeyShares: PublicKeyShareSet,
): PublicKeyShareMaterialSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;

    return createPublicKeyShareMaterialSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        publicMatrixSeedHash,
        publicKeyCrpRoot: String(crpRoots.publicKeyCrpRoot),
        publicAPolynomialRoot: String(publicA.publicPolynomialRoot),
        publicKeyShares,
        materialContributions:
            acceptedPublicKeyShareMaterialContributions(profile),
    });
}

export function acceptedPublicKeyShareProofs(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    publicKeyShares: PublicKeyShareSet,
): PublicKeyShareProofSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const publicKeyCrpRoot = String(crpRoots.publicKeyCrpRoot);
    const publicAPolynomialRoot = String(publicA.publicPolynomialRoot);

    return createPublicKeyShareProofSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        publicKeyShares,
    });
}

const publicKeyShareSuccinctProofBytesHash = (proofBytesHex: string): string =>
    hash512Hex(
        'sealed-lattice/setup/public-key-share/succinct-proof-bytes-v1',
        [hexToBytes(proofBytesHex)],
    );

export function publicKeyShareSuccinctProofsWithDriftedStatementHashes(
    profile: BgvCollectiveSetupProfileDescription,
    setupPackage: JsonRecord,
): PublicKeyShareSuccinctProofSet {
    const setupContext = setupPackage.setupContext as CollectiveBgvSetupContext;
    const commonRandomness = setupPackage.commonRandomness as JsonRecord;
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const setupProofAccountingCertificate = jsonRecord(
        setupPackage.setupProofAccountingCertificate,
        'setupPackage.setupProofAccountingCertificate',
    );
    const publicKeyShares = setupPackage.publicKeyShares as PublicKeyShareSet;
    const proofBytesHex = '00';
    const proofMaterials: PublicKeyShareSuccinctProofMaterial[] =
        publicKeyShares.shareRecords.map((shareRecord) => ({
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            statementHash: validHash('8'),
            proofSizeBytes: 1,
            proofBytesHash: publicKeyShareSuccinctProofBytesHash(proofBytesHex),
            proofBytesHex,
        }));

    return createPublicKeyShareSuccinctProofSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        publicKeyCrpRoot: String(crpRoots.publicKeyCrpRoot),
        publicAPolynomialRoot: String(publicA.publicPolynomialRoot),
        sameSecretConsistency:
            setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet,
        sameSecretProofs: setupPackage.sameSecretProofs as SameSecretProofSet,
        publicKeyShares,
        publicKeyShareProofs:
            setupPackage.publicKeyShareProofs as PublicKeyShareProofSet,
        publicKeyShareMaterial:
            setupPackage.publicKeyShareMaterial as PublicKeyShareMaterialSet,
        proofAccountingHash: String(
            setupProofAccountingCertificate.publicKeyShareProofAccountingHash,
        ),
        proofMaterials,
    });
}
