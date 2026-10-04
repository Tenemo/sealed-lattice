import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileFullWordProofLayout,
    compileWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const publicCoefficientAllowance = 1024n;

export const compileWordProverResources = (
    input: Readonly<{
        columns: number;
        lookups: number;
        preparedAdjointBytes: bigint;
    }>,
) => {
    const agreement = compileCommonAgreementDegreeCensus();
    const layout = compileWordProofLayout(input.columns, input.lookups);
    if (input.preparedAdjointBytes < 0n)
        throw new RangeError('Invalid prepared affine storage size.');
    const field = compileSmallLimbProofFieldCensus();
    const systematic = BigInt(agreement.systematicSize);
    const domain = BigInt(agreement.domainSize);
    const mask = BigInt(agreement.maskDimension);
    const base = field.packedFieldElementByteLength;
    const extension = field.packedExtensionElementByteLength;
    const columns = BigInt(input.columns);
    const lookups = BigInt(input.lookups);
    const preparedAdjointBytes = input.preparedAdjointBytes;
    const witness = 2n * columns * systematic + systematic * base;
    const tree = domain * (2n * 64n + 128n);
    const first =
        tree +
        (columns + 1n) * mask * base +
        BigInt(agreement.codeDimension) * extension;
    const second =
        tree +
        ((lookups + 1n) * mask + 2n * BigInt(agreement.witnessDegree + 1)) *
            extension;
    const linear =
        tree + (BigInt(agreement.witnessDegree) + systematic - 1n) * extension;
    const folding = (domain - 4n) * (extension + 2n * 64n + 128n);
    const reciprocals = systematic * extension;
    // These are explicit allocation allowances, not measured object sizes.
    // The bridge checks the opaque hasher bound before starting work.
    const maximumHasherBytes = 512n;
    const commitmentWorkspace =
        domain * maximumHasherBytes + systematic * (5n * extension + 4n * base);
    const polynomialWorkspace = 12n * systematic * extension;
    const metadataAndAllocatorAllowance = 64n * 1024n * 1024n;
    const stages = [
        ['first oracle', witness + first + commitmentWorkspace],
        [
            'second oracle',
            witness + first + second + reciprocals + commitmentWorkspace,
        ],
        [
            'prepared affine inputs',
            witness +
                first +
                second +
                reciprocals +
                preparedAdjointBytes +
                polynomialWorkspace,
        ],
        [
            'linear oracle',
            witness +
                first +
                second +
                reciprocals +
                linear +
                polynomialWorkspace,
        ],
        [
            'degree combination and folding',
            witness +
                first +
                second +
                linear +
                folding +
                reciprocals +
                polynomialWorkspace,
        ],
        [
            'first openings',
            witness +
                first +
                second +
                linear +
                folding +
                reciprocals +
                polynomialWorkspace +
                3n * BigInt(2 * agreement.queries) * layout.firstWidth,
        ],
        [
            'second openings',
            witness +
                second +
                linear +
                folding +
                reciprocals +
                polynomialWorkspace +
                3n * BigInt(2 * agreement.queries) * layout.secondWidth,
        ],
    ].map(([stage, bytes]) => ({
        stage: stage as string,
        bytes: (bytes as bigint) + metadataAndAllocatorAllowance,
    }));
    return {
        preparedAdjointBytes,
        maximumHasherBytes,
        metadataAndAllocatorAllowance,
        stages,
        maximumLiveBytes: stages.reduce(
            (maximum, stage) => (stage.bytes > maximum ? stage.bytes : maximum),
            0n,
        ),
    };
};

export const compileBrowserWordProverResources = (
    profile: SupportedProfile,
) => {
    const relation = compileSetupContributionRelationCensus(profile);
    const agreement = compileCommonAgreementDegreeCensus();
    const field = compileSmallLimbProofFieldCensus();
    const fullDegreeCommonPolynomials =
        3n * profile.gadgetLength + BigInt(profile.participantCount) + 1n;
    return {
        fullDegreeCommonPolynomials,
        ...compileWordProverResources({
            columns: relation.wordColumns + relation.booleanColumns,
            lookups: relation.lookupEntries,
            preparedAdjointBytes:
                (fullDegreeCommonPolynomials *
                    BigInt(agreement.systematicSize) +
                    auxiliaryInputEncryptionParameters.degree) *
                field.packedExtensionElementByteLength,
        }),
    };
};

export const compileContributionGenerationResources = (
    profile: SupportedProfile,
) => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const auxiliaryDegree = auxiliaryInputEncryptionParameters.degree;
    const participants = BigInt(profile.participantCount);
    const sharingDegree = BigInt(profile.releaseThreshold - 1);
    const roster = compileRosterProposalCensus(Number(participants));
    const retainedRosterPayloadBytes =
        roster.retainedRecordPayloadBytes + roster.proposalBytes;
    const additionalInputBufferBytes = 1_572_864n - (1n << 20n);
    const relation = compileSetupContributionRelationCensus(profile);
    const proof = compileFullWordProofLayout(profile);
    const sparseData = ((participants + 2n) * degree + auxiliaryDegree) * 17n;
    const transforms = 3n * (degree + auxiliaryDegree) * 16n;
    const sharing = sharingDegree * degree * 16n;
    const privateWorkspace = 24n * degree * 16n;
    const publicWorkspace = 4n * degree * publicCoefficientAllowance;
    const generationAllowance =
        relation.syntheticWitnessByteLength +
        sparseData +
        transforms +
        sharing +
        privateWorkspace +
        publicWorkspace +
        64n * 1024n * 1024n;
    const proverAllowance =
        compileBrowserWordProverResources(profile).maximumLiveBytes;
    const gadgetLength = profile.gadgetLength;
    const auxiliaryPolynomialBytes =
        auxiliaryDegree *
        (1n +
            BigInt(
                Math.ceil(
                    auxiliaryInputEncryptionParameters.modulus.toString(2)
                        .length / 8,
                ),
            ));
    const sharingGroupBytes =
        relation.expandedStatementByteLength -
        relation.expandedStatementHeaderByteLength -
        7n * gadgetLength * relation.largestPublicPolynomialByteLength -
        2n * auxiliaryPolynomialBytes;
    const sharingPolynomialBytes = sharingGroupBytes / (3n * participants + 1n);
    if (sharingPolynomialBytes * (3n * participants + 1n) !== sharingGroupBytes)
        throw new Error('Nonintegral sharing statement shape.');
    const regeneratedCommonBytes =
        3n * gadgetLength * relation.largestPublicPolynomialByteLength +
        sharingPolynomialBytes +
        auxiliaryPolynomialBytes;
    return {
        generationAllowance,
        retainedRosterPayloadBytes,
        additionalInputBufferBytes,
        combinedAllowance:
            (generationAllowance > proverAllowance
                ? generationAllowance
                : proverAllowance) +
            2n * 1024n * 1024n +
            retainedRosterPayloadBytes +
            additionalInputBufferBytes,
        publicCoefficientAllowance,
        expandedPublicWorkingBytes:
            relation.expandedStatementByteLength + proof.maximumMultiproofBytes,
        regeneratedCommonBytes,
        reusedRecipientBytes: roster.retainedRecipientKeyBytes,
        publicWorkingBytes:
            relation.expandedStatementByteLength -
            regeneratedCommonBytes -
            roster.retainedRecipientKeyBytes +
            proof.maximumMultiproofBytes,
        maximumPublicEmissionBatch:
            7n * relation.largestPublicPolynomialByteLength,
    };
};
