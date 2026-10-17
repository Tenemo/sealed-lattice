import { committedOfferColumns } from '#tests/committed-offer-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    sourceStatementPolynomialBytes,
    sourceWorkingBytes,
    sourceCiphertextBytes,
    sourceCiphertextPolynomialCount,
} from '#tests/encrypted-registration-source-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileFullWordProofLayout,
    compileWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { merkleTreeStorage } from '#tests/merkle-opening-work-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-relation/shape.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const publicCoefficientAllowance = 1024n;

const compileWordProverResources = (
    input: Readonly<{
        columns: number;
        lookups: number;
        preparedAdjointBytes: bigint;
        publicColumns: number;
        publicLimbs: number;
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
    const tree = merkleTreeStorage(Number(domain), false).residentBytes;
    const forgottenTree = merkleTreeStorage(Number(domain), true).residentBytes;
    const first =
        tree +
        (columns + 1n) * mask * base +
        BigInt(agreement.codeDimension) * extension;
    const second =
        tree +
        ((lookups + 1n) * mask + 2n * BigInt(agreement.witnessDegree + 1)) *
            extension;
    const linear =
        forgottenTree +
        (BigInt(agreement.witnessDegree) + systematic - 1n) * extension;
    let folding = 0n;
    for (let length = Number(domain / 2n); length > 2; length /= 2)
        folding +=
            BigInt(length) * extension +
            merkleTreeStorage(length, true).residentBytes;
    // Tree::new allocates leaves before forget_leaves releases them. Charge
    // that temporary allocation even beside the complete retained state.
    const transientLinearLeaves = domain * 64n;
    const transientFoldingLeaves = (domain / 2n) * 64n;
    const reciprocals = systematic * extension;
    // These are explicit allocation allowances, not measured object sizes.
    // The setup prover checks the opaque hasher bound before starting work.
    const maximumHasherBytes = 512n;
    const commitmentWorkspace =
        domain * maximumHasherBytes + systematic * (5n * extension + 4n * base);
    const polynomialWorkspace = 12n * systematic * extension;
    const metadataAndAllocatorAllowance = 64n * 1024n * 1024n;
    const publicPolynomial = BigInt(input.publicLimbs) * systematic * base;
    const publicTree = 2n * domain * 64n;
    const publicBuilder = domain * maximumHasherBytes + publicPolynomial;
    const publicOpenings =
        3n * BigInt(2 * agreement.queries) * BigInt(input.publicColumns) * base;
    const stages = [
        ['first oracle', witness + first + commitmentWorkspace + publicBuilder],
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
                polynomialWorkspace +
                publicPolynomial,
        ],
        [
            'linear oracle',
            witness +
                first +
                second +
                reciprocals +
                linear +
                polynomialWorkspace +
                transientLinearLeaves,
        ],
        [
            'public oracle',
            witness +
                first +
                second +
                linear +
                reciprocals +
                polynomialWorkspace +
                publicBuilder,
        ],
        [
            'degree combination and folding',
            witness +
                first +
                second +
                linear +
                folding +
                reciprocals +
                polynomialWorkspace +
                publicTree +
                transientFoldingLeaves,
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
                3n * BigInt(2 * agreement.queries) * layout.firstWidth +
                publicTree +
                publicOpenings,
        ],
        [
            'second openings',
            witness +
                second +
                linear +
                folding +
                reciprocals +
                polynomialWorkspace +
                3n * BigInt(2 * agreement.queries) * layout.secondWidth +
                publicTree +
                publicOpenings,
        ],
    ].map(([stage, bytes]) => ({
        stage: stage as string,
        bytes: (bytes as bigint) + metadataAndAllocatorAllowance,
    }));
    return {
        retainedPrivateTreeBytes: tree,
        forgottenPrivateTreeBytes: forgottenTree,
        retainedFoldingBytes: folding,
        preparedAdjointBytes,
        maximumHasherBytes,
        publicPolynomial,
        publicTree,
        publicBuilder,
        publicOpenings,
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
        3n * profile.gadgetLength +
        BigInt(profile.participantCount) +
        1n +
        sourceCiphertextPolynomialCount;
    return {
        fullDegreeCommonPolynomials,
        ...compileWordProverResources({
            columns: relation.wordColumns + relation.booleanColumns,
            lookups: relation.lookupEntries,
            publicColumns: committedOfferColumns(profile),
            publicLimbs: Math.ceil(profile.ciphertext.bits / 96),
            preparedAdjointBytes:
                fullDegreeCommonPolynomials *
                BigInt(agreement.systematicSize) *
                field.packedExtensionElementByteLength,
        }),
    };
};

export const compileContributionGenerationResources = (
    profile: SupportedProfile,
) => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const participants = BigInt(profile.participantCount);
    const sharingDegree = BigInt(profile.releaseThreshold - 1);
    const roster = compileRosterProposalCensus(Number(participants));
    const retainedRosterPayloadBytes =
        roster.retainedRecordPayloadBytes + roster.proposalBytes;
    const additionalInputBufferBytes = 1_572_864n - (1n << 20n);
    const relation = compileSetupContributionRelationCensus(profile);
    const proof = compileFullWordProofLayout(profile);
    const sparseData = (participants + 2n) * degree * 17n;
    const transforms = 3n * degree * 16n;
    const sharing = sharingDegree * degree * 16n;
    const privateWorkspace = 24n * degree * 16n;
    const publicWorkspace = 4n * degree * publicCoefficientAllowance;
    const generationAllowance =
        sourceWorkingBytes +
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
    const sharingGroupBytes =
        relation.expandedStatementByteLength -
        sourceStatementPolynomialBytes -
        relation.expandedStatementHeaderByteLength -
        7n * gadgetLength * relation.largestPublicPolynomialByteLength;
    const sharingPolynomialBytes = sharingGroupBytes / (3n * participants + 1n);
    if (sharingPolynomialBytes * (3n * participants + 1n) !== sharingGroupBytes)
        throw new Error('Nonintegral sharing statement shape.');
    const regeneratedCommonBytes =
        sourceCiphertextBytes +
        3n * gadgetLength * relation.largestPublicPolynomialByteLength +
        sharingPolynomialBytes;
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
