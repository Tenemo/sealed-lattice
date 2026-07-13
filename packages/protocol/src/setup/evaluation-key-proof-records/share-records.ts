import { deriveCanonicalObjectHash } from "@sealed-lattice/crypto";
import type { ProtocolHash } from "@sealed-lattice/types";

import { assertContextMatches, contextFields } from "../common-fields.js";
import { type EvaluatorKeySchedule } from "../evaluator-key-schedule.js";

import {
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchesInput,
    type GaloisKeyShareMaterialRecord,
    type JsonRecord,
    type RelinearizationKeyShareRoundOneRecord,
    type RelinearizationKeyShareRoundTwoRecord,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
    evaluationKeyShareComponentMaterialEncoding,
} from "./constants-and-types.js";
import {
    assertLowercaseHex,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
    evaluationKeyShareComponentVectorRoot,
} from "./encoding.js";

const assertEmbeddedComponentMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    fieldName: string,
): EvaluationKeyShareMaterial &
    EvaluationKeyShareEmbeddedKeySwitchComponentMaterial => {
    if (
        shareMaterial.keySwitchMaterialEncoding !==
        "embedded-full-key-switch-component-vectors"
    ) {
        throw new Error(
            `${fieldName}.keySwitchMaterialEncoding must embed full key-switch component vectors.`,
        );
    }
    if (shareMaterial.keySwitchComponentVectors.length === 0) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectors must be non-empty.`,
        );
    }

    return shareMaterial;
};

const assertShareMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    proofFamily: "relinearization-key-share" | "galois-key-share",
    level: number,
    fieldName: string,
): void => {
    assertNonEmptyString(
        shareMaterial.keySwitchDomain,
        `${fieldName}.keySwitchDomain`,
    );
    assertNonEmptyString(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertLowercaseHex(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertPositiveSafeInteger(
        shareMaterial.ringDegree,
        `${fieldName}.ringDegree`,
    );
    assertProtocolHash(
        shareMaterial.keySwitchComponentVectorRoot,
        `${fieldName}.keySwitchComponentVectorRoot`,
    );
    if (
        shareMaterial.keySwitchMaterialEncoding ===
        "embedded-full-key-switch-component-vectors"
    ) {
        if (shareMaterial.keySwitchComponentVectors.length === 0) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectors must be non-empty.`,
            );
        }
        shareMaterial.keySwitchComponentVectors.forEach(
            (componentVector, vectorIndex) => {
                assertJsonRecord(
                    componentVector,
                    `${fieldName}.keySwitchComponentVectors.${String(vectorIndex)}`,
                );
            },
        );
        if (
            evaluationKeyShareComponentVectorRoot(
                proofFamily,
                shareMaterial.keySwitchDomain,
                shareMaterial.keySwitchSeedHex,
                level,
                shareMaterial.ringDegree,
                shareMaterial.keySwitchComponentVectors,
            ) !== shareMaterial.keySwitchComponentVectorRoot
        ) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectorRoot must match the embedded public material.`,
            );
        }
    } else if (
        shareMaterial.keySwitchMaterialEncoding ===
        evaluationKeyShareComponentMaterialEncoding
    ) {
        assertProtocolHash(
            shareMaterial.keySwitchComponentMaterialRoot,
            `${fieldName}.keySwitchComponentMaterialRoot`,
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be embedded-full-key-switch-component-vectors or binary-chunked-key-switch-component-vectors.`,
        );
    }
};

const shareMaterialRecordFields = (
    shareMaterial: EvaluationKeyShareMaterial,
): JsonRecord => ({
    keySwitchComponentVectorRoot: shareMaterial.keySwitchComponentVectorRoot,
    ...(shareMaterial.keySwitchMaterialEncoding ===
    "embedded-full-key-switch-component-vectors"
        ? {
              keySwitchComponentVectors:
                  shareMaterial.keySwitchComponentVectors,
          }
        : {
              keySwitchComponentMaterialRoot:
                  shareMaterial.keySwitchComponentMaterialRoot,
          }),
});

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
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
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
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

const assertRelinearizationKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: "round-one" | "round-two",
    level: number,
    fieldName: string,
): void => {
    if (shareMaterial.keySwitchDomain !== "relinearization") {
        throw new Error(
            `${fieldName}.keySwitchDomain must be relinearization.`,
        );
    }
    const expectedSeed = relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled relinearization level and round.`,
        );
    }
};

const assertGaloisKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
    fieldName: string,
): void => {
    const expectedDomain = `galois-${String(rotation)}`;
    if (shareMaterial.keySwitchDomain !== expectedDomain) {
        throw new Error(
            `${fieldName}.keySwitchDomain must match the scheduled Galois rotation.`,
        );
    }
    const expectedSeed = galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled Galois rotation and level.`,
        );
    }
};

const sortedTrusteeReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        "participantCount" | "trusteeReferences"
    >,
): EvaluationKeyTrusteeReference[] => {
    const references = [...input.trusteeReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.participantCount) {
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
    assertPositiveSafeInteger(input.participantCount, "participantCount");
    if (input.qSharePrimes.length === 0) {
        throw new Error("qSharePrimes must contain at least one RNS prime.");
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        "evaluatorKeySchedule",
    );
    for (const [fieldName, hashValue] of [
        [
            "evaluatorKeyScheduleRoot",
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        ],
        [
            "publicKeyShareSetRoot",
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        [
            "publicKeyShareSuccinctProofSetRoot",
            input.publicKeyShareSuccinctProofSetRoot,
        ],
        [
            "relinearizationCrpRoot",
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        ],
        ["galoisKeyCrpRoot", input.evaluatorKeySchedule.galoisKeyCrpRoot],
        [
            "requiredGaloisSetHash",
            input.evaluatorKeySchedule.requiredGaloisSetHash,
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
    const roundOneAggregateRootByLevel = new Map<number, ProtocolHash>();
    const roundOneAggregateRoots = levels.map((level) => {
        const roundOneRecordRootsForLevel = trusteeReferences.map(
            (trusteeReference) => {
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
                assertShareMaterial(
                    contribution.shareMaterial,
                    "relinearization-key-share",
                    level,
                    "roundOneContributions.shareMaterial",
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    "round-one",
                    level,
                    "roundOneContributions.shareMaterial",
                );
                const recordWithoutRoot = {
                    objectType: "RelinearizationKeyShareRoundOne",
                    ...contextFields(input.setupContext),
                    trusteeIdentity: trusteeReference.trusteeIdentity,
                    trusteeRosterPosition:
                        trusteeReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundOneRecordRoot =
                    deriveCanonicalObjectHash(recordWithoutRoot);
                roundOneRecords.push({
                    ...recordWithoutRoot,
                    roundOneRecordRoot,
                } as RelinearizationKeyShareRoundOneRecord);

                return {
                    trusteeIdentity: trusteeReference.trusteeIdentity,
                    trusteeRosterPosition:
                        trusteeReference.trusteeRosterPosition,
                    roundOneRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = deriveCanonicalObjectHash({
            objectType: "RelinearizationRoundOneAggregate",
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            level,
            roundOneRecordRoots: roundOneRecordRootsForLevel,
        });
        roundOneAggregateRootByLevel.set(level, roundOneAggregateRoot);

        return {
            level,
            roundOneAggregateRoot,
        };
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    const roundTwoAggregateRoots = levels.map((level) => {
        const roundTwoRecordRootsForLevel = trusteeReferences.map(
            (trusteeReference) => {
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
                assertShareMaterial(
                    contribution.shareMaterial,
                    "relinearization-key-share",
                    level,
                    "roundTwoContributions.shareMaterial",
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    "round-two",
                    level,
                    "roundTwoContributions.shareMaterial",
                );
                const recordWithoutRoot = {
                    objectType: "RelinearizationKeyShareRoundTwo",
                    ...contextFields(input.setupContext),
                    trusteeIdentity: trusteeReference.trusteeIdentity,
                    trusteeRosterPosition:
                        trusteeReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundTwoRecordRoot =
                    deriveCanonicalObjectHash(recordWithoutRoot);
                roundTwoRecords.push({
                    ...recordWithoutRoot,
                    roundTwoRecordRoot,
                } as RelinearizationKeyShareRoundTwoRecord);

                return {
                    trusteeIdentity: trusteeReference.trusteeIdentity,
                    trusteeRosterPosition:
                        trusteeReference.trusteeRosterPosition,
                    roundTwoRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = roundOneAggregateRootByLevel.get(level);
        if (roundOneAggregateRoot === undefined) {
            throw new Error(
                "roundTwoContributions is missing a scheduled round-one aggregate root.",
            );
        }
        const roundTwoAggregateRoot = deriveCanonicalObjectHash({
            objectType: "RelinearizationRoundTwoAggregate",
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            level,
            roundOneAggregateRoot,
            roundTwoRecordRoots: roundTwoRecordRootsForLevel,
        });

        return {
            level,
            roundTwoAggregateRoot,
        };
    });

    const roundsWithoutRoot = {
        objectType: "RelinearizationKeyShareRounds",
        ...contextFields(input.setupContext),
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        roundOneAggregateRoots,
        roundOneRecords,
        roundTwoAggregateRoots,
        roundTwoRecords,
    } as const satisfies Omit<
        RelinearizationKeyShareRounds,
        "relinearizationKeyShareRoundsRoot"
    >;

    return {
        ...roundsWithoutRoot,
        relinearizationKeyShareRoundsRoot:
            deriveCanonicalObjectHash(roundsWithoutRoot),
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
            (shareContribution, index) => {
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
                assertShareMaterial(
                    shareContribution.shareMaterial,
                    "galois-key-share",
                    shareContribution.level,
                    "galoisKeyShares.shareMaterial",
                );
                assertGaloisKeySwitchSampleBinding(
                    shareContribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    shareContribution.rotation,
                    shareContribution.level,
                    "galoisKeyShares.shareMaterial",
                );

                return {
                    objectType: "GaloisKeyShareMaterial",
                    rotation: shareContribution.rotation,
                    level: shareContribution.level,
                    ...shareMaterialRecordFields(
                        shareContribution.shareMaterial,
                    ),
                } as GaloisKeyShareMaterialRecord;
            },
        );
        const batchWithoutRoot = {
            objectType: "GaloisKeyShareBatch",
            ...contextFields(input.setupContext),
            trusteeIdentity: trusteeReference.trusteeIdentity,
            trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            publicKeyShareSuccinctProofSetRoot:
                input.publicKeyShareSuccinctProofSetRoot,
            galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
            requiredGaloisSetHash:
                input.evaluatorKeySchedule.requiredGaloisSetHash,
            galoisKeyShareMaterialRecords,
        } as const satisfies Omit<
            GaloisKeyShareBatch,
            "galoisKeyShareBatchRoot"
        >;

        return {
            ...batchWithoutRoot,
            galoisKeyShareBatchRoot:
                deriveCanonicalObjectHash(batchWithoutRoot),
        } satisfies GaloisKeyShareBatch;
    });
};

export { assertContextMatches, assertEmbeddedComponentMaterial, contextFields };
