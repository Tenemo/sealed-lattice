import { foundationProfile, type ProtocolHash } from "@sealed-lattice/types";

import { copyCanonicalStreamDescriptor } from "../canonical-stream-descriptor.js";
import type { CanonicalProofMaterialChunkPull } from "../setup-proof-material-transport.js";

import {
    type BinaryChunkedEvaluationKeyShareMaterialTransport,
    type EvaluationKeyShareComponentMaterialTransportInput,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyShareMaterialTransportInput,
    type EvaluationKeyShareProofFamily,
    type EvaluationKeyTrusteeReference,
    type TransportedEvaluationKeyShareComponentMaterial,
    evaluationKeyShareComponentMaterialMagic,
} from "./constants-and-types.js";
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertJsonRecord,
    bytesFromHex,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentMaterialReferenceRoot,
    evaluationKeyShareComponentVectorRoot,
    stringRecordField,
} from "./encoding.js";
import {
    galoisKeySwitchSeed,
    relinearizationKeySwitchSeed,
} from "./share-records.js";

type EvaluationKeyShareTransportWorkItem = Readonly<{
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly shareMaterial: EvaluationKeyShareComponentMaterialTransportInput;
}>;

const trusteeIdentityByRosterPosition = (
    trusteeReferences: readonly EvaluationKeyTrusteeReference[],
): ReadonlyMap<number, string> => {
    const identities = new Map<number, string>();
    trusteeReferences.forEach((reference, referenceIndex) => {
        assertNonEmptyString(
            reference.trusteeIdentity,
            `trusteeReferences.${String(referenceIndex)}.trusteeIdentity`,
        );
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            `trusteeReferences.${String(referenceIndex)}.trusteeRosterPosition`,
        );
        if (identities.has(reference.trusteeRosterPosition)) {
            throw new Error(
                "trusteeReferences must not repeat trusteeRosterPosition.",
            );
        }
        identities.set(
            reference.trusteeRosterPosition,
            reference.trusteeIdentity,
        );
    });

    return identities;
};

const trusteeIdentityForContribution = (
    identities: ReadonlyMap<number, string>,
    trusteeRosterPosition: number,
    fieldName: string,
): string => {
    const trusteeIdentity = identities.get(trusteeRosterPosition);
    if (trusteeIdentity === undefined) {
        throw new Error(
            `${fieldName} references a trustee roster position without a trustee reference.`,
        );
    }

    return trusteeIdentity;
};

type CanonicalComponentVector = Readonly<{
    readonly coefficientsLeHex: string;
}>;

type ValidatedComponentMaterial = Readonly<{
    readonly componentVectors: readonly CanonicalComponentVector[];
    readonly componentVectorRoot: ProtocolHash;
    readonly totalByteLength: number;
}>;

const validatedEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    shareMaterial: EvaluationKeyShareComponentMaterialTransportInput,
    level: number,
    ringDegree: number,
    qSharePrimes: readonly number[],
): ValidatedComponentMaterial => {
    assertNonNegativeSafeInteger(level, "level");
    assertPositiveSafeInteger(ringDegree, "ringDegree");
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(
            "evaluation-key component material level is outside the Q_share basis.",
        );
    }
    if (!Array.isArray(shareMaterial.keySwitchComponentVectors)) {
        throw new TypeError(
            "evaluation-key component material must supply component vectors before transport.",
        );
    }
    if (shareMaterial.keySwitchComponentVectors.length !== digitCount ** 2) {
        throw new Error(
            "evaluation-key component material must contain one vector per scheduled digit and RNS limb.",
        );
    }
    const canonicalComponentVectors: CanonicalComponentVector[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const componentVector = assertJsonRecord(
                shareMaterial.keySwitchComponentVectors[
                    digitIndex * digitCount + rnsLimbIndex
                ],
                "keySwitchComponentVectors",
            );
            const vectorPath = `keySwitchComponentVectors.${String(
                digitIndex,
            )}.${String(rnsLimbIndex)}`;
            const rnsPrime = qSharePrimes[rnsLimbIndex];
            const coefficientsLeHex = stringRecordField(
                componentVector,
                "coefficientsLeHex",
                vectorPath,
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
                ringDegree,
                `${vectorPath}.coefficientsLeHex`,
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    "evaluation-key component material coefficients must be canonical residues.",
                );
            }
            canonicalComponentVectors.push({
                coefficientsLeHex,
            });
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        canonicalComponentVectors,
    );
    const totalByteLength =
        evaluationKeyShareComponentMaterialMagic.byteLength +
        canonicalComponentVectors.length * ringDegree * 8;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            "evaluation-key component material byte length is outside the JavaScript safe integer range.",
        );
    }

    return {
        componentVectors: canonicalComponentVectors,
        componentVectorRoot,
        totalByteLength,
    };
};

const evaluationKeyShareComponentMaterialSegments = function* (
    ringDegree: number,
    validatedMaterial: ValidatedComponentMaterial,
): Generator<Uint8Array> {
    const header = new Uint8Array(evaluationKeyShareComponentMaterialMagic);
    header.set(evaluationKeyShareComponentMaterialMagic);
    yield header;

    for (const componentVector of validatedMaterial.componentVectors) {
        const coefficientBytes = bytesFromHex(
            componentVector.coefficientsLeHex,
            "evaluation-key component coefficientsLeHex",
        );
        if (coefficientBytes.byteLength !== ringDegree * 8) {
            throw new Error(
                "evaluation-key component coefficient bytes must match ringDegree.",
            );
        }
        yield coefficientBytes;
    }
};

const sequentialChunkPull = (
    segments: Generator<Uint8Array>,
    totalByteLength: number,
): CanonicalProofMaterialChunkPull => {
    let currentSegment: Uint8Array | undefined;
    let currentSegmentOffset = 0;
    let nextChunkIndex = 0;
    let emittedByteLength = 0;

    return ({ chunkIndex, expectedByteLength }) =>
        Promise.resolve().then(() => {
            if (chunkIndex !== nextChunkIndex) {
                throw new Error(
                    "evaluation-key component material chunks must be pulled in ascending order.",
                );
            }
            if (emittedByteLength === totalByteLength) {
                if (expectedByteLength !== 0) {
                    throw new Error(
                        "evaluation-key component material source was pulled past its declared length.",
                    );
                }
                nextChunkIndex += 1;
                return undefined;
            }
            const remainingByteLength = totalByteLength - emittedByteLength;
            const requiredByteLength = Math.min(
                foundationProfile.streamChunkByteLength,
                remainingByteLength,
            );
            if (expectedByteLength !== requiredByteLength) {
                throw new Error(
                    "evaluation-key component material pull length does not match the canonical chunk boundary.",
                );
            }
            const chunk = new Uint8Array(requiredByteLength);
            let writeOffset = 0;
            while (writeOffset < chunk.length) {
                if (
                    currentSegment === undefined ||
                    currentSegmentOffset === currentSegment.length
                ) {
                    currentSegment?.fill(0);
                    const nextSegment = segments.next();
                    if (nextSegment.done) {
                        throw new Error(
                            "evaluation-key component material encoder ended before its declared length.",
                        );
                    }
                    currentSegment = nextSegment.value;
                    currentSegmentOffset = 0;
                }
                const copyByteLength = Math.min(
                    currentSegment.length - currentSegmentOffset,
                    chunk.length - writeOffset,
                );
                chunk.set(
                    currentSegment.subarray(
                        currentSegmentOffset,
                        currentSegmentOffset + copyByteLength,
                    ),
                    writeOffset,
                );
                currentSegmentOffset += copyByteLength;
                writeOffset += copyByteLength;
            }
            emittedByteLength += chunk.length;
            nextChunkIndex += 1;

            return chunk.buffer;
        });
};

const transportEvaluationKeyShareComponentMaterial = async (
    workItem: EvaluationKeyShareTransportWorkItem,
    writeComponentMaterial: EvaluationKeyShareMaterialTransportInput["writeEvaluationKeyShareComponentMaterial"],
    ringDegree: number,
    qSharePrimes: readonly number[],
): Promise<
    Readonly<{
        readonly shareMaterial: EvaluationKeyShareMaterial;
        readonly componentMaterial: TransportedEvaluationKeyShareComponentMaterial;
    }>
> => {
    const validatedMaterial = validatedEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.keySwitchDomain,
        workItem.keySwitchSeedHex,
        workItem.shareMaterial,
        workItem.level,
        ringDegree,
        qSharePrimes,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            ringDegree,
            validatedMaterial.componentVectorRoot,
            workItem.keySwitchDomain,
            workItem.keySwitchSeedHex,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
        );
    const shareMaterial: EvaluationKeyShareMaterial = {
        keySwitchComponentMaterialRoot,
    };
    const descriptorBytes = copyCanonicalStreamDescriptor(
        await writeComponentMaterial({
            keySwitchComponentMaterialRoot,
            proofFamily: workItem.proofFamily,
            pullChunk: sequentialChunkPull(
                evaluationKeyShareComponentMaterialSegments(
                    ringDegree,
                    validatedMaterial,
                ),
                validatedMaterial.totalByteLength,
            ),
            totalByteLength: validatedMaterial.totalByteLength,
        }),
        "writeEvaluationKeyShareComponentMaterial descriptorBytes",
    );

    return {
        shareMaterial,
        componentMaterial: {
            keySwitchComponentMaterialRoot,
            descriptorBytes,
        },
    };
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = async (
    input: EvaluationKeyShareMaterialTransportInput,
): Promise<BinaryChunkedEvaluationKeyShareMaterialTransport> => {
    if (!Array.isArray(input.qSharePrimes) || input.qSharePrimes.length === 0) {
        throw new Error("qSharePrimes must contain at least one RNS prime.");
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertPositiveSafeInteger(input.ringDegree, "ringDegree");
    const identities = trusteeIdentityByRosterPosition(input.trusteeReferences);
    const componentMaterials: TransportedEvaluationKeyShareComponentMaterial[] =
        [];
    const componentRoots = new Set<string>();
    const transportShareMaterial = async (
        workItem: EvaluationKeyShareTransportWorkItem,
    ): Promise<EvaluationKeyShareMaterial> => {
        const componentTransport =
            await transportEvaluationKeyShareComponentMaterial(
                workItem,
                input.writeEvaluationKeyShareComponentMaterial,
                input.ringDegree,
                input.qSharePrimes,
            );
        const componentMaterialRoot =
            componentTransport.componentMaterial.keySwitchComponentMaterialRoot;
        if (componentRoots.has(componentMaterialRoot)) {
            throw new Error(
                "transported evaluation-key component material contains duplicate roots.",
            );
        }
        componentRoots.add(componentMaterialRoot);
        componentMaterials.push(componentTransport.componentMaterial);

        return componentTransport.shareMaterial;
    };

    const relinearizationRoundOneContributions: BinaryChunkedEvaluationKeyShareMaterialTransport["relinearizationRoundOneContributions"][number][] =
        [];
    for (const contribution of input.relinearizationRoundOneContributions) {
        relinearizationRoundOneContributions.push({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            shareMaterial: await transportShareMaterial({
                proofFamily: "relinearization-key-share",
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    "relinearizationRoundOneContributions",
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                keySwitchDomain: "relinearization",
                keySwitchSeedHex: relinearizationKeySwitchSeed(
                    input.evaluatorKeySchedule,
                    "round-one",
                    contribution.level,
                ),
                shareMaterial: contribution.shareMaterial,
            }),
        });
    }
    const relinearizationRoundTwoContributions: BinaryChunkedEvaluationKeyShareMaterialTransport["relinearizationRoundTwoContributions"][number][] =
        [];
    for (const contribution of input.relinearizationRoundTwoContributions) {
        relinearizationRoundTwoContributions.push({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            shareMaterial: await transportShareMaterial({
                proofFamily: "relinearization-key-share",
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    "relinearizationRoundTwoContributions",
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                keySwitchDomain: "relinearization",
                keySwitchSeedHex: relinearizationKeySwitchSeed(
                    input.evaluatorKeySchedule,
                    "round-two",
                    contribution.level,
                ),
                shareMaterial: contribution.shareMaterial,
            }),
        });
    }
    const galoisKeyShareBatchContributions: BinaryChunkedEvaluationKeyShareMaterialTransport["galoisKeyShareBatchContributions"][number][] =
        [];
    for (const batchContribution of input.galoisKeyShareBatchContributions) {
        const trusteeIdentity = trusteeIdentityForContribution(
            identities,
            batchContribution.trusteeRosterPosition,
            "galoisKeyShareBatchContributions",
        );
        const galoisKeyShares: BinaryChunkedEvaluationKeyShareMaterialTransport["galoisKeyShareBatchContributions"][number]["galoisKeyShares"][number][] =
            [];
        for (const shareContribution of batchContribution.galoisKeyShares) {
            galoisKeyShares.push({
                rotation: shareContribution.rotation,
                level: shareContribution.level,
                shareMaterial: await transportShareMaterial({
                    proofFamily: "galois-key-share",
                    trusteeIdentity,
                    trusteeRosterPosition:
                        batchContribution.trusteeRosterPosition,
                    level: shareContribution.level,
                    keySwitchDomain: `galois-${String(
                        shareContribution.rotation,
                    )}`,
                    keySwitchSeedHex: galoisKeySwitchSeed(
                        input.evaluatorKeySchedule,
                        shareContribution.rotation,
                        shareContribution.level,
                    ),
                    shareMaterial: shareContribution.shareMaterial,
                }),
            });
        }
        galoisKeyShareBatchContributions.push({
            trusteeRosterPosition: batchContribution.trusteeRosterPosition,
            galoisKeyShares,
        });
    }

    return {
        relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions,
        transportedEvaluationKeyShareComponentMaterial: {
            componentMaterials,
        },
    };
};
