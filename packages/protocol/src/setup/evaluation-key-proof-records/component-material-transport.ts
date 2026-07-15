import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';

import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { CanonicalProofMaterialChunkPull } from '../setup-proof-material-transport.js';

import {
    type BinaryChunkedEvaluationKeyShareMaterialTransport,
    type EvaluationKeyShareComponentMaterialStream,
    type EvaluationKeyShareMaterialTransportInput,
    type EvaluationKeyShareProofFamily,
    type EvaluationKeyTrusteeReference,
    evaluationKeyShareComponentMaterialMagic,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    bytesFromHex,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentMaterialReferenceRoot,
    evaluationKeyShareComponentVectorRoot,
} from './encoding.js';
import {
    galoisKeySwitchSeed,
    relinearizationKeySwitchSeed,
} from './share-records.js';

type EvaluationKeyShareTransportWorkItem = Readonly<{
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly keySwitchDomain: string;
    readonly keySwitchSeedHex: string;
    readonly keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
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
                'trusteeReferences must not repeat trusteeRosterPosition.',
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

type ValidatedComponentMaterial = Readonly<{
    readonly componentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
    readonly componentVectorRoot: ProtocolHash;
    readonly ringDegree: number;
    readonly totalByteLength: number;
}>;

const validatedEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[],
    level: number,
    qSharePrimes: readonly number[],
): ValidatedComponentMaterial => {
    assertNonNegativeSafeInteger(level, 'level');
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(
            'evaluation-key component material level is outside the Q_share basis.',
        );
    }
    const componentVectorValues: unknown =
        keySwitchComponentVectorsLittleEndianHexByDigitAndLimb;
    if (!Array.isArray(componentVectorValues)) {
        throw new TypeError(
            'evaluation-key component material must supply component vectors before transport.',
        );
    }
    if (componentVectorValues.length !== digitCount ** 2) {
        throw new Error(
            'evaluation-key component material must contain one vector per scheduled digit and RNS limb.',
        );
    }
    const firstComponentVectorHex: unknown = componentVectorValues[0];
    if (
        typeof firstComponentVectorHex !== 'string' ||
        firstComponentVectorHex.length === 0 ||
        firstComponentVectorHex.length % 16 !== 0
    ) {
        throw new TypeError(
            'keySwitchComponentVectorsLittleEndianHexByDigitAndLimb.0.0 must encode complete 64-bit coefficients.',
        );
    }
    const ringDegree = firstComponentVectorHex.length / 16;
    assertPositiveSafeInteger(ringDegree, 'derived ringDegree');
    const canonicalComponentVectorsLittleEndianHexByDigitAndLimb: string[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const vectorPath = `keySwitchComponentVectorsLittleEndianHexByDigitAndLimb.${String(
                digitIndex,
            )}.${String(rnsLimbIndex)}`;
            const rnsPrime = qSharePrimes[rnsLimbIndex];
            const coefficientsLeHex: unknown =
                componentVectorValues[digitIndex * digitCount + rnsLimbIndex];
            if (
                typeof coefficientsLeHex !== 'string' ||
                coefficientsLeHex.length === 0
            ) {
                throw new TypeError(`${vectorPath} must be non-empty.`);
            }
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
                ringDegree,
                `${vectorPath}.coefficientsLeHex`,
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'evaluation-key component material coefficients must be canonical residues.',
                );
            }
            canonicalComponentVectorsLittleEndianHexByDigitAndLimb.push(
                coefficientsLeHex,
            );
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        canonicalComponentVectorsLittleEndianHexByDigitAndLimb,
    );
    const totalByteLength =
        evaluationKeyShareComponentMaterialMagic.byteLength +
        canonicalComponentVectorsLittleEndianHexByDigitAndLimb.length *
            ringDegree *
            8;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            'evaluation-key component material byte length is outside the JavaScript safe integer range.',
        );
    }

    return {
        componentVectorsLittleEndianHexByDigitAndLimb:
            canonicalComponentVectorsLittleEndianHexByDigitAndLimb,
        componentVectorRoot,
        ringDegree,
        totalByteLength,
    };
};

const evaluationKeyShareComponentMaterialSegments = function* (
    validatedMaterial: ValidatedComponentMaterial,
): Generator<Uint8Array> {
    const header = new Uint8Array(evaluationKeyShareComponentMaterialMagic);
    header.set(evaluationKeyShareComponentMaterialMagic);
    yield header;

    for (const coefficientsLeHex of validatedMaterial.componentVectorsLittleEndianHexByDigitAndLimb) {
        const coefficientBytes = bytesFromHex(
            coefficientsLeHex,
            'evaluation-key component coefficientsLeHex',
        );
        if (coefficientBytes.byteLength !== validatedMaterial.ringDegree * 8) {
            throw new Error(
                'evaluation-key component coefficient bytes must match ringDegree.',
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
                    'evaluation-key component material chunks must be pulled in ascending order.',
                );
            }
            if (emittedByteLength === totalByteLength) {
                if (expectedByteLength !== 0) {
                    throw new Error(
                        'evaluation-key component material source was pulled past its declared length.',
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
                    'evaluation-key component material pull length does not match the canonical chunk boundary.',
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
                            'evaluation-key component material encoder ended before its declared length.',
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
    writeComponentMaterial: EvaluationKeyShareMaterialTransportInput['writeEvaluationKeyShareComponentMaterial'],
    qSharePrimes: readonly number[],
): Promise<
    Readonly<{
        readonly keySwitchComponentMaterialRoot: ProtocolHash;
        readonly componentMaterialStream: EvaluationKeyShareComponentMaterialStream;
    }>
> => {
    const validatedMaterial = validatedEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.keySwitchDomain,
        workItem.keySwitchSeedHex,
        workItem.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
        workItem.level,
        qSharePrimes,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            validatedMaterial.componentVectorRoot,
            workItem.keySwitchDomain,
            workItem.keySwitchSeedHex,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
        );
    const writtenMaterial = await writeComponentMaterial({
        keySwitchComponentMaterialRoot,
        proofFamily: workItem.proofFamily,
        pullChunk: sequentialChunkPull(
            evaluationKeyShareComponentMaterialSegments(validatedMaterial),
            validatedMaterial.totalByteLength,
        ),
        totalByteLength: validatedMaterial.totalByteLength,
    });
    if (typeof writtenMaterial.pullChunk !== 'function') {
        throw new TypeError(
            'writeEvaluationKeyShareComponentMaterial pullChunk must be a function.',
        );
    }
    const descriptorBytes = copyCanonicalStreamDescriptor(
        writtenMaterial.descriptorBytes,
        'writeEvaluationKeyShareComponentMaterial descriptorBytes',
    );

    return {
        keySwitchComponentMaterialRoot,
        componentMaterialStream: {
            descriptorBytes,
            pullChunk: writtenMaterial.pullChunk,
        },
    };
};

type RelinearizationMaterialContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly keySwitchComponentVectorsLittleEndianHexByDigitAndLimb: readonly string[];
}>;

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

const relinearizationContributionsByKey = (
    contributions: readonly RelinearizationMaterialContribution[],
    fieldName: string,
    trusteeIdentities: ReadonlyMap<number, string>,
): ReadonlyMap<string, RelinearizationMaterialContribution> => {
    const contributionsByKey = new Map<
        string,
        RelinearizationMaterialContribution
    >();
    contributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            `${fieldName}.trusteeRosterPosition`,
        );
        trusteeIdentityForContribution(
            trusteeIdentities,
            contribution.trusteeRosterPosition,
            fieldName,
        );
        assertNonNegativeSafeInteger(contribution.level, `${fieldName}.level`);
        const key = contributionKey(
            contribution.level,
            contribution.trusteeRosterPosition,
        );
        if (contributionsByKey.has(key)) {
            throw new Error(
                `${fieldName} must not repeat a trustee and level.`,
            );
        }
        contributionsByKey.set(key, contribution);
    });

    return contributionsByKey;
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = async (
    input: EvaluationKeyShareMaterialTransportInput,
): Promise<BinaryChunkedEvaluationKeyShareMaterialTransport> => {
    if (!Array.isArray(input.qSharePrimes) || input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    const identities = trusteeIdentityByRosterPosition(input.trusteeReferences);
    const canonicalTrusteeRosterPositions = [...identities.keys()].sort(
        (left, right) => left - right,
    );
    canonicalTrusteeRosterPositions.forEach(
        (trusteeRosterPosition, expectedRosterPosition) => {
            if (trusteeRosterPosition !== expectedRosterPosition) {
                throw new Error(
                    'trusteeReferences roster positions must be contiguous from zero.',
                );
            }
        },
    );
    const evaluationKeyShareComponentMaterialStreams: EvaluationKeyShareComponentMaterialStream[] =
        [];
    const componentRoots = new Set<string>();
    const transportComponentMaterial = async (
        workItem: EvaluationKeyShareTransportWorkItem,
    ): Promise<ProtocolHash> => {
        const componentTransport =
            await transportEvaluationKeyShareComponentMaterial(
                workItem,
                input.writeEvaluationKeyShareComponentMaterial,
                input.qSharePrimes,
            );
        const componentMaterialRoot =
            componentTransport.keySwitchComponentMaterialRoot;
        if (componentRoots.has(componentMaterialRoot)) {
            throw new Error(
                'transported evaluation-key component material contains duplicate roots.',
            );
        }
        componentRoots.add(componentMaterialRoot);
        evaluationKeyShareComponentMaterialStreams.push(
            componentTransport.componentMaterialStream,
        );

        return componentMaterialRoot;
    };

    const scheduledLevels =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            ({ level }) => level,
        );
    const roundOneContributionsByKey = relinearizationContributionsByKey(
        input.relinearizationRoundOneContributions,
        'relinearizationRoundOneContributions',
        identities,
    );
    const roundTwoContributionsByKey = relinearizationContributionsByKey(
        input.relinearizationRoundTwoContributions,
        'relinearizationRoundTwoContributions',
        identities,
    );
    const expectedRelinearizationContributionCount =
        scheduledLevels.length * canonicalTrusteeRosterPositions.length;
    if (
        roundOneContributionsByKey.size !==
            expectedRelinearizationContributionCount ||
        roundTwoContributionsByKey.size !==
            expectedRelinearizationContributionCount
    ) {
        throw new Error(
            'relinearization contributions must contain exactly one material per scheduled trustee and level.',
        );
    }
    const relinearizationRoundOneContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['relinearizationRoundOneContributions'][number][] =
        [];
    for (const level of scheduledLevels) {
        for (const trusteeRosterPosition of canonicalTrusteeRosterPositions) {
            const contribution = roundOneContributionsByKey.get(
                contributionKey(level, trusteeRosterPosition),
            );
            if (contribution === undefined) {
                throw new Error(
                    'relinearizationRoundOneContributions is missing a scheduled trustee and level.',
                );
            }
            relinearizationRoundOneContributions.push({
                trusteeRosterPosition,
                level,
                keySwitchComponentMaterialRoot:
                    await transportComponentMaterial({
                        proofFamily: 'relinearization-key-share',
                        trusteeIdentity: trusteeIdentityForContribution(
                            identities,
                            trusteeRosterPosition,
                            'relinearizationRoundOneContributions',
                        ),
                        trusteeRosterPosition,
                        level,
                        keySwitchDomain: 'relinearization',
                        keySwitchSeedHex: relinearizationKeySwitchSeed(
                            input.evaluatorKeySchedule,
                            'round-one',
                            level,
                        ),
                        keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                            contribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
                    }),
            });
        }
    }
    const relinearizationRoundTwoContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['relinearizationRoundTwoContributions'][number][] =
        [];
    for (const level of scheduledLevels) {
        for (const trusteeRosterPosition of canonicalTrusteeRosterPositions) {
            const contribution = roundTwoContributionsByKey.get(
                contributionKey(level, trusteeRosterPosition),
            );
            if (contribution === undefined) {
                throw new Error(
                    'relinearizationRoundTwoContributions is missing a scheduled trustee and level.',
                );
            }
            relinearizationRoundTwoContributions.push({
                trusteeRosterPosition,
                level,
                keySwitchComponentMaterialRoot:
                    await transportComponentMaterial({
                        proofFamily: 'relinearization-key-share',
                        trusteeIdentity: trusteeIdentityForContribution(
                            identities,
                            trusteeRosterPosition,
                            'relinearizationRoundTwoContributions',
                        ),
                        trusteeRosterPosition,
                        level,
                        keySwitchDomain: 'relinearization',
                        keySwitchSeedHex: relinearizationKeySwitchSeed(
                            input.evaluatorKeySchedule,
                            'round-two',
                            level,
                        ),
                        keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                            contribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
                    }),
            });
        }
    }
    const galoisBatchContributionsByRosterPosition = new Map(
        input.galoisKeyShareBatchContributions.map((batchContribution) => {
            assertNonNegativeSafeInteger(
                batchContribution.trusteeRosterPosition,
                'galoisKeyShareBatchContributions.trusteeRosterPosition',
            );
            return [
                batchContribution.trusteeRosterPosition,
                batchContribution,
            ] as const;
        }),
    );
    if (
        galoisBatchContributionsByRosterPosition.size !==
        input.galoisKeyShareBatchContributions.length
    ) {
        throw new Error(
            'galoisKeyShareBatchContributions must not repeat a trustee roster position.',
        );
    }
    if (
        galoisBatchContributionsByRosterPosition.size !==
        canonicalTrusteeRosterPositions.length
    ) {
        throw new Error(
            'galoisKeyShareBatchContributions must contain one batch per trustee.',
        );
    }
    const galoisKeyShareBatchContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['galoisKeyShareBatchContributions'][number][] =
        [];
    for (const trusteeRosterPosition of canonicalTrusteeRosterPositions) {
        const batchContribution = galoisBatchContributionsByRosterPosition.get(
            trusteeRosterPosition,
        );
        if (batchContribution === undefined) {
            throw new Error(
                'galoisKeyShareBatchContributions is missing a trustee batch.',
            );
        }
        const trusteeIdentity = trusteeIdentityForContribution(
            identities,
            trusteeRosterPosition,
            'galoisKeyShareBatchContributions',
        );
        if (
            batchContribution.galoisKeyShares.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'galoisKeyShares must contain one share per required Galois key.',
            );
        }
        const galoisKeyShares: BinaryChunkedEvaluationKeyShareMaterialTransport['galoisKeyShareBatchContributions'][number]['galoisKeyShares'][number][] =
            [];
        for (const [
            scheduleIndex,
            scheduleEntry,
        ] of input.evaluatorKeySchedule.requiredGaloisKeySchedule.entries()) {
            const shareContribution =
                batchContribution.galoisKeyShares[scheduleIndex];
            if (
                shareContribution === undefined ||
                shareContribution.rotation !== scheduleEntry.rotation ||
                shareContribution.level !== scheduleEntry.level
            ) {
                throw new Error(
                    'galoisKeyShares must follow the frozen Galois key schedule.',
                );
            }
            galoisKeyShares.push({
                rotation: shareContribution.rotation,
                level: shareContribution.level,
                keySwitchComponentMaterialRoot:
                    await transportComponentMaterial({
                        proofFamily: 'galois-key-share',
                        trusteeIdentity,
                        trusteeRosterPosition,
                        level: shareContribution.level,
                        keySwitchDomain: `galois-${String(
                            shareContribution.rotation,
                        )}`,
                        keySwitchSeedHex: galoisKeySwitchSeed(
                            input.evaluatorKeySchedule,
                            shareContribution.rotation,
                            shareContribution.level,
                        ),
                        keySwitchComponentVectorsLittleEndianHexByDigitAndLimb:
                            shareContribution.keySwitchComponentVectorsLittleEndianHexByDigitAndLimb,
                    }),
            });
        }
        galoisKeyShareBatchContributions.push({
            trusteeRosterPosition,
            galoisKeyShares,
        });
    }

    return {
        relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions,
        evaluationKeyShareComponentMaterialStreams,
    };
};
