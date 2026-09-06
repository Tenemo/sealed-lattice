import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { maximumSharedPathSiblings } from '#tests/merkle-path-sharing-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export const compileRegistrationKeyRelationCensus = () => {
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const prime = compileSmallLimbProofFieldCensus().modulus;
    const modulus = prime * 998244353n;
    const radix = 1n << 96n,
        support = 256n,
        error = 64n;
    const signedWordBound = 1n << 15n;
    const halfModulus = modulus / 2n;
    const honestQuotient = ((support + 1n) * halfModulus + error) / modulus;
    const honestCarry =
        ((support + 1n + honestQuotient) * (radix - 1n) + error) / radix;
    const maximumLimbResidual =
        (support + 1n + signedWordBound) * (radix - 1n) +
        signedWordBound * (radix + 1n) +
        error;
    if (
        maximumLimbResidual >= prime ||
        honestQuotient >= signedWordBound ||
        honestCarry >= signedWordBound
    )
        throw new Error('Registration lifting bounds fail.');
    const wordColumns = 3,
        booleanColumns = 2,
        lookups = 4,
        disjointPairs = 1;
    const originalOracles = wordColumns + booleanColumns + lookups + 4;
    const virtualOracles = booleanColumns + disjointPairs + lookups + 2;
    const agreement = compileCommonAgreementDegreeCensus();
    const firstLeafBytes = BigInt(wordColumns + booleanColumns + 1) * 16n + 48n;
    const secondLeafBytes = BigInt(lookups + 2) * 48n;
    const folds = Math.log2(agreement.domainSize / 2);
    const proofHeaderBytes =
        4n +
        5n * 64n +
        48n +
        BigInt(folds + 3) * 128n +
        BigInt(folds - 1) * 64n +
        48n;
    const group = (length: number, width: bigint) => {
        const count = Math.min(2 * agreement.queries, length);
        return (
            4n +
            BigInt(count) * (4n + width + 128n) +
            BigInt(maximumSharedPathSiblings(length, count)) * 64n
        );
    };
    let maximumProofBytes =
        proofHeaderBytes +
        group(agreement.domainSize, firstLeafBytes) +
        group(agreement.domainSize, secondLeafBytes) +
        group(agreement.domainSize, 48n);
    for (let length = agreement.domainSize / 2; length > 2; length /= 2)
        maximumProofBytes += group(length, 48n);
    return {
        degree,
        modulus,
        radix,
        support,
        error,
        honestQuotient,
        honestCarry,
        maximumLimbResidual,
        wordColumns,
        booleanColumns,
        lookups,
        disjointPairs,
        originalOracles,
        virtualOracles,
        affineRows: 2n * degree + 2n,
        headerBytes: 4n + 4n + 20n,
        publicKeyBytes: degree * 21n,
        statementBytes: 4n + 4n + 20n + 2n * degree * 21n,
        firstLeafBytes,
        secondLeafBytes,
        proofHeaderBytes,
        maximumProofBytes,
        maximumCoefficientQueryBytes:
            BigInt(2 * agreement.queries * (wordColumns + booleanColumns)) *
            48n,
    };
};

export const registrationIntegerRows = (
    common: readonly bigint[],
    key: readonly bigint[],
    secret: readonly bigint[],
    errors: readonly bigint[],
    quotient: readonly bigint[],
    carry: readonly bigint[],
    modulus: bigint,
    radix: bigint,
) => {
    const degree = common.length;
    if (
        [key, secret, errors, quotient, carry].some(
            (values) => values.length !== degree,
        )
    )
        throw new Error('Inconsistent registration polynomial shapes.');
    const digit = (value: bigint, limb: number) => {
        const magnitude =
            ((value < 0n ? -value : value) / radix ** BigInt(limb)) % radix;
        return value < 0n ? -magnitude : magnitude;
    };
    return [0, 1].flatMap((limb) =>
        Array.from({ length: degree }, (_unused, output) => {
            let product = 0n;
            for (let input = 0; input < degree; input++)
                product +=
                    secret[input] *
                    digit(common[(output + degree - input) % degree], limb) *
                    (output < input ? -1n : 1n);
            return (
                product +
                digit(key[output], limb) -
                digit(modulus, limb) * quotient[output] -
                (limb === 0
                    ? errors[output] + radix * carry[output]
                    : -carry[output])
            );
        }),
    );
};
