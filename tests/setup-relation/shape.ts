import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    sourceCiphertextPolynomialCount,
    sourceStatementPolynomialBytes,
    sourceStatementPolynomialCount,
} from '#tests/encrypted-registration-source-model.js';
import { integerLimbConvolutionMagnitudeBound } from '#tests/exact-integer-convolution-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    shareModulus,
    createSetupContributionRelationModel,
} from '#tests/setup-contribution-relation-model.js';
import {
    fheRadix,
    setupEquationWidths,
} from '#tests/setup-relation/equations.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { type SupportedProfile } from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

const columnLayout = (
    model: ReturnType<typeof createSetupContributionRelationModel>,
) => {
    const wordColumns = model.columns.filter(
        ({ kind }) => kind === 'word',
    ).length;
    const booleanColumns = model.columns.length - wordColumns;
    let nextWord = 0,
        nextBoolean = wordColumns;
    const modelToCanonicalColumn = model.columns.map(({ kind }) =>
        kind === 'word' ? nextWord++ : nextBoolean++,
    );
    return {
        wordColumns,
        booleanColumns,
        modelToCanonicalColumn,
        lookups: [
            ...Array.from({ length: wordColumns }, (_unused, column) => ({
                column,
                scale: 1n,
            })),
            ...model.columns.flatMap((column, index) =>
                column.kind === 'word' && column.bits < 16
                    ? [
                          {
                              column: modelToCanonicalColumn[index],
                              scale: 1n << BigInt(16 - column.bits),
                          },
                      ]
                    : [],
            ),
        ],
        disjointBooleanPairs: model.disjointPairs.map(
            ([positive, negative]) =>
                [
                    modelToCanonicalColumn[positive],
                    modelToCanonicalColumn[negative],
                ] as const,
        ),
    };
};

export const compileSetupContributionColumnLayout = (
    profile: SupportedProfile,
) => columnLayout(createSetupContributionRelationModel(profile));

// Columns of one signed variable: whole 16-bit words then one Boolean column
// per remaining bit, or a single narrow word when it is narrower than a word.
const signedVariableColumns = (bits: number) =>
    bits < 16
        ? { words: 1, narrowWords: 1, booleans: 0 }
        : { words: Math.floor(bits / 16), narrowWords: 0, booleans: bits % 16 };

// The column and row counts of the full-size relation, from the variable
// families that the reduced model allocates. Tests compare them with the
// executed model's layout.
export const deriveSetupContributionShape = (profile: SupportedProfile) => {
    const participants = profile.participantCount;
    const sharingDegree = profile.releaseThreshold - 1;
    const { sharingCoefficientBits, limbBits, carryBits } =
        profile.shareLifting;
    const fheLimbs = Math.ceil(
        profile.ciphertext.modulus.toString(2).length / 96,
    );
    const gadgetLength = Number(profile.gadgetLength);
    const fheEquations = 4 * gadgetLength;
    const { quotientBits, fheCarryBits, errorBits } = setupEquationWidths;
    const variableBits = [
        // FHE key equations: quotient, carries and error.
        ...Array.from({ length: fheEquations }, () => [
            quotientBits,
            ...Array.from({ length: fheLimbs - 1 }, () => fheCarryBits),
            errorBits,
        ]).flat(),
        // Sharing coefficients: low and high limb parts.
        ...Array.from({ length: sharingDegree }, () => [
            limbBits,
            sharingCoefficientBits - limbBits,
        ]).flat(),
        // Each recipient's constant and linear share equations.
        ...Array.from({ length: participants }, () => [
            quotientBits,
            carryBits,
            errorBits,
            quotientBits,
            fheCarryBits,
            errorBits,
        ]).flat(),
    ];
    const columns = variableBits.map(signedVariableColumns);
    // The FHE secret, FHE auxiliary secret and recipient ephemerals each
    // have a positive and a negative column.
    const disjointPairs = participants + 3;
    const sourceEquations = Number(sourceCiphertextPolynomialCount);
    const wordColumns =
        2 * sourceEquations +
        columns.reduce((sum, value) => sum + value.words, 0);
    const narrowWords =
        sourceEquations +
        columns.reduce((sum, value) => sum + value.narrowWords, 0);
    const booleanColumns =
        2 * disjointPairs +
        columns.reduce((sum, value) => sum + value.booleans, 0);
    const supportRows = 2 * disjointPairs;
    return {
        wordColumns,
        booleanColumns,
        errorColumns:
            sourceEquations +
            variableBits.filter((bits) => bits === errorBits).length,
        disjointPairs,
        supportRows,
        lookupEntries: wordColumns + narrowWords,
        affineRows:
            BigInt(
                fheEquations * fheLimbs + 4 * participants + sourceEquations,
            ) *
                fixedModulusBfvInputs.polynomialDegree +
            BigInt(supportRows),
    };
};

export const compileSetupContributionRelationCensus = (
    profile: SupportedProfile,
) => {
    const shape = deriveSetupContributionShape(profile);
    const columnCount = BigInt(shape.wordColumns + shape.booleanColumns);
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const field = compileSmallLimbProofFieldCensus();
    const extensionElementByteLength = field.packedExtensionElementByteLength;
    const agreement = compileCommonAgreementDegreeCensus();
    const maximumPublicQueryCount = 2 * agreement.queries;
    const publicQueryValueByteLength =
        BigInt(maximumPublicQueryCount) * extensionElementByteLength;
    const singlePublicAdjointCoefficientByteLength =
        degree * extensionElementByteLength;
    const publicCoefficientMagnitudeByteLength =
        BigInt(profile.ciphertext.modulus.toString(2).length + 7) / 8n;
    const shareMagnitudeByteLength =
        BigInt(shareModulus.toString(2).length + 7) / 8n;
    const fheStatementPolynomials = 7n * profile.gadgetLength;
    const sharingStatementPolynomials =
        3n * BigInt(profile.participantCount) + 1n;
    const largestConvolutionOneNorm = [
        fixedModulusBfvInputs.secretSupportWeight,
        shareEncryptionParameters.encryptionSupportWeight,
    ].reduce((maximum, value) => (value > maximum ? value : maximum), 0n);
    // The widest limb of any equation bounds every limb convolution.
    const maximumIntegerLimbConvolutionMagnitude =
        integerLimbConvolutionMagnitudeBound(
            fheRadix,
            largestConvolutionOneNorm,
            field.modulus,
        );
    const syntheticWitnessHeaderByteLength = 4n + 3n * 4n + 64n;
    const expandedStatementHeaderByteLength =
        4n + publicCoefficientMagnitudeByteLength;
    return {
        ...shape,
        fullAffineCoefficientByteLength:
            columnCount * singlePublicAdjointCoefficientByteLength,
        singlePublicAdjointCoefficientByteLength,
        largestPublicPolynomialByteLength:
            degree * (1n + publicCoefficientMagnitudeByteLength),
        maximumPublicQueryCount,
        publicQueryValueByteLength,
        fullAffineQueryValueByteLength:
            columnCount * publicQueryValueByteLength,
        publicQueryTransformVectorByteLength:
            2n * singlePublicAdjointCoefficientByteLength +
            (degree / 2n) * field.packedFieldElementByteLength +
            publicQueryValueByteLength,
        fullRingQueryCosets: BigInt(agreement.domainSize) / degree,
        expandedStatementPolynomialCount:
            fheStatementPolynomials +
            sharingStatementPolynomials +
            sourceStatementPolynomialCount,
        expandedStatementHeaderByteLength,
        expandedStatementByteLength:
            sourceStatementPolynomialBytes +
            expandedStatementHeaderByteLength +
            fheStatementPolynomials *
                degree *
                (1n + publicCoefficientMagnitudeByteLength) +
            sharingStatementPolynomials *
                degree *
                (1n + shareMagnitudeByteLength),
        maximumEncodedOperatorByteLength:
            64n +
            2n * extensionElementByteLength +
            columnCount * publicQueryValueByteLength,
        maximumIntegerLimbConvolutionMagnitude,
        syntheticWitnessHeaderByteLength,
        syntheticWitnessByteLength:
            syntheticWitnessHeaderByteLength + 2n * degree * columnCount,
    };
};
