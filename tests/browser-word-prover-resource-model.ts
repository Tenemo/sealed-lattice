import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export const compileBrowserWordProverResources = () => {
    const agreement = compileCommonAgreementDegreeCensus();
    const relation = compileSetupContributionRelationCensus();
    const layout = compileFullWordProofLayout();
    const field = compileSmallLimbProofFieldCensus();
    const systematic = BigInt(agreement.systematicSize);
    const domain = BigInt(agreement.domainSize);
    const mask = BigInt(agreement.maskDimension);
    const base = field.packedFieldElementByteLength;
    const extension = field.packedExtensionElementByteLength;
    const columns = BigInt(relation.wordColumns + relation.booleanColumns);
    const lookups = BigInt(relation.lookupEntries);
    let gadgetLength = 0n;
    for (
        let value = 1n;
        value < fixedModulusBfvInputs.ciphertextModulus;
        value *= fixedModulusBfvInputs.gadgetBase
    )
        gadgetLength++;
    const fullDegreeCommonPolynomials =
        3n * gadgetLength + fixedModulusBfvInputs.participantCount + 1n;
    const preparedAdjointBytes =
        (fullDegreeCommonPolynomials * systematic +
            auxiliaryInputEncryptionParameters.degree) *
        extension;
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
        fullDegreeCommonPolynomials,
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
