import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { maximumSharedPathSiblings } from '#tests/merkle-path-sharing-model.js';
import { compileSetupContributionColumnLayout } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

export const compileFullWordProofLayout = () => {
    const agreement = compileCommonAgreementDegreeCensus();
    const columns = compileSetupContributionColumnLayout();
    const field = compileSmallLimbProofFieldCensus();
    const compiler = compileWideChallengeCompilerCensus();
    const wordCount = columns.wordColumns + columns.booleanColumns;
    const foldCount = Math.log2(agreement.domainSize / 2);
    const tagBytes = compiler.tagBits / 8n;
    const saltBytes = compiler.saltBits / 8n;
    const baseBytes = field.packedFieldElementByteLength;
    const extensionBytes = field.packedExtensionElementByteLength;
    const firstWidth = BigInt(wordCount + 1) * baseBytes + extensionBytes;
    const secondWidth = BigInt(columns.lookups.length + 2) * extensionBytes;
    const headerBytes =
        4n +
        2n * tagBytes +
        3n * tagBytes +
        extensionBytes +
        BigInt(foldCount + 3) * saltBytes +
        BigInt(foldCount - 1) * tagBytes +
        extensionBytes;
    let maximumProofBytes = headerBytes;
    let maximumMultiproofBytes = headerBytes;
    let maximumCachedNodes = 0;
    let totalLeaves = 3n * BigInt(agreement.domainSize);
    const openingGroup = (length: number, width: bigint) =>
        4n +
        BigInt(Math.min(2 * agreement.queries, length)) *
            (4n + width + saltBytes + BigInt(Math.log2(length)) * tagBytes);
    const multiproofGroup = (length: number, width: bigint) => {
        const count = Math.min(2 * agreement.queries, length);
        const siblings = maximumSharedPathSiblings(length, count);
        maximumCachedNodes = Math.max(maximumCachedNodes, 2 * siblings);
        return (
            4n +
            BigInt(count) * (4n + width + saltBytes) +
            BigInt(siblings) * tagBytes
        );
    };
    for (const width of [firstWidth, secondWidth, extensionBytes]) {
        maximumProofBytes += openingGroup(agreement.domainSize, width);
        maximumMultiproofBytes += multiproofGroup(agreement.domainSize, width);
    }
    for (let length = agreement.domainSize / 2; length > 2; length /= 2) {
        maximumProofBytes += openingGroup(length, extensionBytes);
        maximumMultiproofBytes += multiproofGroup(length, extensionBytes);
        totalLeaves += BigInt(length);
    }
    return {
        foldCount,
        headerBytes,
        firstWidth,
        secondWidth,
        maximumProofBytes,
        maximumMultiproofBytes,
        maximumCachedNodeDigestBytes: BigInt(maximumCachedNodes) * tagBytes,
        proverInterpolationPoints: agreement.codeDimension,
        expandedFirstOracleBytes: firstWidth * BigInt(agreement.domainSize),
        expandedSecondOracleBytes: secondWidth * BigInt(agreement.domainSize),
        leafSaltBytes: totalLeaves * saltBytes,
        proverMaskBytes:
            BigInt(wordCount + 1) *
                BigInt(agreement.maskDimension) *
                baseBytes +
            BigInt(agreement.codeDimension) * extensionBytes +
            BigInt(columns.lookups.length + 1) *
                BigInt(agreement.maskDimension) *
                extensionBytes +
            BigInt(agreement.witnessDegree + 1) * extensionBytes,
    };
};

// A high-degree term aliases to a constant on the prover's smaller
// interpolation domain. Verification must retain the complete domain.
export const proverInterpolationAlias = () => {
    const prime = 97n,
        root = 28n,
        coset = 2n,
        length = 32,
        dimension = 16;
    const modulo = (value: bigint) => ((value % prime) + prime) % prime;
    const points = Array.from(
        { length },
        (_unused, index) => (coset * root ** BigInt(index)) % prime,
    );
    const claimedConstant = coset ** BigInt(dimension) % prime;
    const actual = points.map((point) => point ** BigInt(dimension) % prime);
    return {
        points,
        claimedConstant,
        actual,
        evenAgreement: actual.every(
            (value, index) => index % 2 !== 0 || value === claimedConstant,
        ),
        oddDifference: actual
            .filter((_value, index) => index % 2 !== 0)
            .map((value) => modulo(value - claimedConstant)),
    };
};
