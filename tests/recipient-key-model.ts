import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export const compileRecipientKeyCensus = () => {
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
    return {
        degree,
        modulus,
        radix,
        support,
        error,
        honestQuotient,
        honestCarry,
        maximumLimbResidual,
        publicKeyBytes:
            degree * (1n + BigInt(Math.ceil(modulus.toString(2).length / 8))),
    };
};

export const recipientKeyIntegerRows = (
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
