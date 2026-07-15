import { deriveCanonicalObjectHash } from "@sealed-lattice/crypto";
import type { ProtocolHash } from "@sealed-lattice/types";

import { assertSetupContextHashMatches } from "../common-fields.js";
import {
    deriveEvaluatorKeyScheduleRoot,
    type EvaluatorKeySchedule,
} from "../evaluator-key-schedule.js";

import {
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchesInput,
    type GaloisKeyShareMaterialRecord,
    type RelinearizationKeyShareRoundOneRecord,
    type RelinearizationKeyShareRoundTwoRecord,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
} from "./constants-and-types.js";
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
} from "./encoding.js";

const assertShareMaterialRoot = (
    shareMaterial: Pick<
        EvaluationKeyShareMaterial,
        "keySwitchComponentMaterialRoot"
    >,
    fieldName: string,
): void => {
    assertProtocolHash(
        shareMaterial.keySwitchComponentMaterialRoot,
        `${fieldName}.keySwitchComponentMaterialRoot`,
    );
};

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

export const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: "round-one" | "round-two",
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: "RelinearizationKeySwitchPublicSampleSeed",
        publicMatrixSeedHash: evaluatorKeySchedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot:
            deriveEvaluatorKeyScheduleRoot(evaluatorKeySchedule),
        round,
        level,
    });

export const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: "GaloisKeySwitchPublicSampleSeed",
        publicMatrixSeedHash: evaluatorKeySchedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot:
            deriveEvaluatorKeyScheduleRoot(evaluatorKeySchedule),
        rotation,
        level,
    });

const sortedTrusteeReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        "setupContext" | "trusteeReferences"
    >,
): EvaluationKeyTrusteeReference[] => {
    const references = [...input.trusteeReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.setupContext.participantCount) {
        throw new Error(
            "trusteeReferences must contain one trustee per participant.",
        );
    }
    references.forEach((reference, expectedRosterPosition) => {
        assertNonEmptyString(reference.trusteeIdentity, "trusteeIdentity");
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            "trusteeRosterPosition",
        );
        if (reference.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                "trusteeReferences roster positions must be contiguous from zero.",
            );
        }
    });

    return references;
};

export const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): EvaluationKeyTrusteeReference[] => {
    assertPositiveSafeInteger(
        input.setupContext.participantCount,
        "setupContext.participantCount",
    );
    if (input.qSharePrimes.length === 0) {
        throw new Error("qSharePrimes must contain at least one RNS prime.");
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertSetupContextHashMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        "evaluatorKeySchedule",
    );
    for (const [fieldName, hashValue] of [
        [
            "publicKeyShareSetRoot",
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        [
            "publicMatrixSeedHash",
            input.evaluatorKeySchedule.publicMatrixSeedHash,
        ],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }

    return sortedTrusteeReferences(input);
};

const contributionMap = <
    Contribution extends {
        readonly trusteeRosterPosition: number;
        readonly level: number;
    },
>(
    contributions: readonly Contribution[],
    fieldName: string,
): ReadonlyMap<string, Contribution> => {
    const byKey = new Map<string, Contribution>();
    contributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            `${fieldName}.trusteeRosterPosition`,
        );
        assertNonNegativeSafeInteger(contribution.level, `${fieldName}.level`);
        const key = contributionKey(
            contribution.level,
            contribution.trusteeRosterPosition,
        );
        if (byKey.has(key)) {
            throw new Error(
                `${fieldName} must not repeat a trustee and level.`,
            );
        }
        byKey.set(key, contribution);
    });

    return byKey;
};

export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds => {
    const trusteeReferences = validateCommonInput(input);
    const roundOneContributions = contributionMap(
        input.roundOneContributions,
        "roundOneContributions",
    );
    const roundTwoContributions = contributionMap(
        input.roundTwoContributions,
        "roundTwoContributions",
    );
    const levels = input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
        (entry) => entry.level,
    );
    const roundOneRecords: RelinearizationKeyShareRoundOneRecord[] = [];
    levels.forEach((level) => {
        trusteeReferences.forEach((trusteeReference) => {
            const key = contributionKey(
                level,
                trusteeReference.trusteeRosterPosition,
            );
            const contribution = roundOneContributions.get(key);
            if (contribution === undefined) {
                throw new Error(
                    "roundOneContributions is missing a scheduled trustee and level.",
                );
            }
            assertShareMaterialRoot(
                contribution.shareMaterial,
                "roundOneContributions.shareMaterial",
            );
            roundOneRecords.push({
                objectType: "RelinearizationKeyShareRoundOne",
                keySwitchComponentMaterialRoot:
                    contribution.shareMaterial.keySwitchComponentMaterialRoot,
            });
        });
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    levels.forEach((level) => {
        trusteeReferences.forEach((trusteeReference) => {
            const key = contributionKey(
                level,
                trusteeReference.trusteeRosterPosition,
            );
            const contribution = roundTwoContributions.get(key);
            if (contribution === undefined) {
                throw new Error(
                    "roundTwoContributions is missing a scheduled trustee and level.",
                );
            }
            assertShareMaterialRoot(
                contribution.shareMaterial,
                "roundTwoContributions.shareMaterial",
            );
            roundTwoRecords.push({
                objectType: "RelinearizationKeyShareRoundTwo",
                keySwitchComponentMaterialRoot:
                    contribution.shareMaterial.keySwitchComponentMaterialRoot,
            });
        });
    });

    return {
        objectType: "RelinearizationKeyShareRounds",
        roundOneRecords,
        roundTwoRecords,
    } satisfies RelinearizationKeyShareRounds;
};

export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    const trusteeReferences = validateCommonInput(input);
    const contributionsByRosterPosition = new Map<
        number,
        GaloisKeyShareBatchContribution
    >();
    input.batchContributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            "batchContributions.trusteeRosterPosition",
        );
        if (
            contributionsByRosterPosition.has(
                contribution.trusteeRosterPosition,
            )
        ) {
            throw new Error(
                "batchContributions must not repeat a trustee roster position.",
            );
        }
        contributionsByRosterPosition.set(
            contribution.trusteeRosterPosition,
            contribution,
        );
    });

    return trusteeReferences.map((trusteeReference) => {
        const contribution = contributionsByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (contribution === undefined) {
            throw new Error(
                "batchContributions must contain one batch per participant.",
            );
        }
        if (
            contribution.galoisKeyShares.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                "galoisKeyShares must contain one share per required Galois key.",
            );
        }
        const galoisKeyShareMaterialRecords = contribution.galoisKeyShares.map(
            (shareContribution, index): GaloisKeyShareMaterialRecord => {
                const expectedScheduleEntry =
                    input.evaluatorKeySchedule.requiredGaloisKeySchedule[index];
                if (
                    shareContribution.rotation !==
                        expectedScheduleEntry.rotation ||
                    shareContribution.level !== expectedScheduleEntry.level
                ) {
                    throw new Error(
                        "galoisKeyShares must follow the frozen Galois key schedule.",
                    );
                }
                assertShareMaterialRoot(
                    shareContribution.shareMaterial,
                    "galoisKeyShares.shareMaterial",
                );

                return {
                    objectType: "GaloisKeyShareMaterial",
                    keySwitchComponentMaterialRoot:
                        shareContribution.shareMaterial
                            .keySwitchComponentMaterialRoot,
                };
            },
        );
        return {
            objectType: "GaloisKeyShareBatch",
            galoisKeyShareMaterialRecords,
        } satisfies GaloisKeyShareBatch;
    });
};

export { assertSetupContextHashMatches };
