import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export type Column = {
    name: string;
    bits: number;
    kind: 'word' | 'boolean';
    values: bigint[];
};

export type Variable = Readonly<{
    terms: readonly { column: number; factor: bigint }[];
    offset: bigint;
    stride: number;
}>;

type Term = Readonly<{ column: number; position: number; factor: bigint }>;

export type Row = { constant: bigint; terms: Term[] };

type ConvolutionTerm = Readonly<{
    publicCoefficients: readonly bigint[];
    variable: Variable;
}>;

// A sharing coefficient c = low + radix*high + radix/2, with its low and
// high limb parts as separate signed variables.
type MonomialTerm = Readonly<{
    low: Variable;
    high: Variable;
    exponent: number;
    factor: bigint;
}>;

export type Equation = Readonly<{
    name: string;
    modulus: bigint;
    degree: number;
    publicValue: bigint[];
    publicSign: bigint;
    convolution: readonly ConvolutionTerm[];
    direct: readonly {
        variable: Variable;
        factor: bigint;
        automorphism?: number;
    }[];
    shifts?: readonly MonomialTerm[];
    offset?: readonly bigint[];
    quotient: Variable;
    carries: readonly Variable[];
    error: Variable;
    errorSign: bigint;
    limbs: number;
    radix: bigint;
}>;

// FHE equations use 96-bit limbs; share equations use the
// profile's share-lifting limb.
export const fheRadix = 1n << 96n;

// Every setup equation has a signed quotient and error of these widths. The
// FHE key equations and the linear share equations have carries of the FHE
// carry width; the constant share equations use the profile's share carry.
export const setupEquationWidths = {
    quotientBits: 16,
    fheCarryBits: 16,
    errorBits: 7,
} as const;

export const prime = compileSmallLimbProofFieldCensus().modulus;

export const modulo = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;

const digit = (value: bigint, limb: number, radix: bigint) =>
    (value < 0n ? -1n : 1n) *
    (((value < 0n ? -value : value) / radix ** BigInt(limb)) % radix);

const append = (
    row: Row,
    variable: Variable,
    position: number,
    factor: bigint,
) => {
    row.constant += variable.offset * factor;
    for (const term of variable.terms)
        row.terms.push({
            column: term.column,
            position: position * variable.stride,
            factor: factor * term.factor,
        });
};

export const compileSetupEquation = (
    equation: Equation,
    degree: number,
): Row[] => {
    const rows: Row[] = [];
    for (let limb = 0; limb < equation.limbs; limb++)
        for (let position = 0; position < equation.degree; position++) {
            const row: Row = {
                constant:
                    equation.publicSign *
                        digit(
                            equation.publicValue[position],
                            limb,
                            equation.radix,
                        ) +
                    digit(
                        equation.offset?.[position] ?? 0n,
                        limb,
                        equation.radix,
                    ),
                terms: [],
            };
            for (const term of equation.convolution)
                for (let index = 0; index < equation.degree; index++)
                    append(
                        row,
                        term.variable,
                        (position - index + equation.degree) % equation.degree,
                        (position < index ? -1n : 1n) *
                            digit(
                                term.publicCoefficients[index],
                                limb,
                                equation.radix,
                            ),
                    );
            for (const term of equation.direct) {
                if (term.automorphism === undefined)
                    append(
                        row,
                        term.variable,
                        position,
                        digit(term.factor, limb, equation.radix),
                    );
                else
                    for (let index = 0; index < equation.degree; index++) {
                        const exponent = term.automorphism * index;
                        if (exponent % equation.degree === position)
                            append(
                                row,
                                term.variable,
                                index,
                                (Math.floor(exponent / equation.degree) % 2 ===
                                0
                                    ? 1n
                                    : -1n) *
                                    digit(term.factor, limb, equation.radix),
                            );
                    }
            }
            for (const term of equation.shifts ?? []) {
                const shift =
                    ((term.exponent % (2 * degree)) + 2 * degree) %
                    (2 * degree);
                const input = (((position - shift) % degree) + degree) % degree;
                const sign =
                    Math.floor((input + shift) / degree) % 2 === 0 ? 1n : -1n;
                append(
                    row,
                    limb === 0 ? term.low : term.high,
                    input,
                    sign * term.factor,
                );
            }
            if (limb === 0)
                append(row, equation.error, position, equation.errorSign);
            append(
                row,
                equation.quotient,
                position,
                -digit(equation.modulus, limb, equation.radix),
            );
            if (limb > 0) append(row, equation.carries[limb - 1], position, 1n);
            if (limb < equation.limbs - 1)
                append(row, equation.carries[limb], position, -equation.radix);
            rows.push(row);
        }
    return rows;
};
