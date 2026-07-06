import {
    coefficientVectorLittleEndianHex,
    minimumSuccinctProofFixtureRingDegree,
    publicKeyShareCoefficientVectorHash,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import {
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
} from '#packages/protocol/src/setup/public-key-share-records';
import { type SameSecretConsistencyStatementSet } from '#packages/protocol/src/setup/same-secret-consistency-records';
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
        { length: parameters.participantCount },
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
        participantCount: parameters.participantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        shareContributions: publicKeyShareContributionsFromMaterial(
            acceptedPublicKeyShareMaterialContributions(parameters),
        ),
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
        participantCount: parameters.participantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        publicKeyShares,
    });
}
