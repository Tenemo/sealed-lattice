import { validHash } from '../../bgv-passive-setup-fixtures.js';
import {
    coefficientVectorLittleEndianHex,
    firstRosterParticipantCount,
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
    type SameSecretConsistencyStatementSet,
    type SameSecretProofSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type { BgvCollectiveSetupParametersDescription } from '#packages/wasm/src/index';

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
    parameters: BgvCollectiveSetupParametersDescription,
): PublicKeyShareMaterialContributionInput[] =>
    Array.from(
        { length: firstRosterParticipantCount },
        (_unusedTrustee, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
            shareCoefficientVectorsByLimb: parameters.qShare.primes.map(
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
    parameters: BgvCollectiveSetupParametersDescription,
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
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        shareContributions: publicKeyShareContributionsFromMaterial(
            acceptedPublicKeyShareMaterialContributions(parameters),
        ),
    });
}

export function acceptedPublicKeyShareMaterial(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    commonRandomness: JsonRecord,
    publicKeyShares: PublicKeyShareSet,
): PublicKeyShareMaterialSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;

    return createPublicKeyShareMaterialSet({
        setupContext,
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        publicMatrixSeedHash,
        publicKeyCrpRoot: String(crpRoots.publicKeyCrpRoot),
        publicAPolynomialRoot: String(publicA.publicPolynomialRoot),
        publicKeyShares,
        materialContributions:
            acceptedPublicKeyShareMaterialContributions(parameters),
    });
}

export function acceptedPublicKeyShareProofs(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
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
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
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
    parameters: BgvCollectiveSetupParametersDescription,
    setupPackage: JsonRecord,
): PublicKeyShareSuccinctProofSet {
    const setupContext = setupPackage.setupContext as CollectiveBgvSetupContext;
    const commonRandomness = setupPackage.commonRandomness as JsonRecord;
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const canonicalSuccinctProofs = jsonRecord(
        setupPackage.publicKeyShareSuccinctProofs,
        'setupPackage.publicKeyShareSuccinctProofs',
    );
    const publicKeyShares = setupPackage.publicKeyShares as PublicKeyShareSet;
    const proofBytesHex = '00';
    const proofMaterials: PublicKeyShareSuccinctProofMaterial[] =
        publicKeyShares.shareRecords.map((shareRecord) => ({
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
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
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
            canonicalSuccinctProofs.proofAccountingHash,
        ),
        proofMaterials,
    });
}
