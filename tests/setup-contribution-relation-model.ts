import assert from 'node:assert/strict';

import { isCanonicalCenteredPolynomial } from '#tests/canonical-polynomial-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { integerLimbConvolutionMagnitudeBound } from '#tests/exact-integer-convolution-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    fingerprintSignedLimbs,
    geometricNegacyclicAdjoint,
} from '#tests/geometric-ring-adjoint-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    interpolationRingDegree,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

type Column = {
    name: string;
    bits: number;
    kind: 'word' | 'boolean';
    values: bigint[];
};
type Variable = Readonly<{
    terms: readonly { column: number; factor: bigint }[];
    offset: bigint;
    stride: number;
}>;
type Term = Readonly<{ column: number; position: number; factor: bigint }>;
type Row = { constant: bigint; terms: Term[] };
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
type Equation = Readonly<{
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
const fheRadix = 1n << 96n;
const prime = compileSmallLimbProofFieldCensus().modulus;
const shareScale = shareEncryptionParameters.scale;
const shareModulus = shareEncryptionParameters.modulus;
const modulo = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;
const center = (value: bigint, modulus: bigint) => {
    const result = modulo(value, modulus);
    return result > modulus / 2n ? result - modulus : result;
};
const digit = (value: bigint, limb: number, radix: bigint) =>
    (value < 0n ? -1n : 1n) *
    (((value < 0n ? -value : value) / radix ** BigInt(limb)) % radix);
const convolution = (
    left: readonly bigint[],
    right: readonly bigint[],
): bigint[] => {
    assert.equal(left.length, right.length);
    const result = left.map(() => 0n);
    for (let first = 0; first < left.length; first++)
        for (let second = 0; second < right.length; second++)
            result[(first + second) % left.length] +=
                (first + second >= left.length ? -1n : 1n) *
                left[first] *
                right[second];
    return result;
};
const addPolynomials = (...values: readonly (readonly bigint[])[]): bigint[] =>
    values[0].map((_value, index) =>
        values.reduce((sum, row) => sum + row[index], 0n),
    );

// The physical degrees and sparse supports are reduced. Moduli, signed sharing
// interval, gadget coordinates, and every distinct equation family are retained.
export const createSetupContributionRelationModel = (
    profile: SupportedProfile,
    seed = 1n,
) => {
    const degree = 16;
    const participants = profile.participantCount;
    const sharingDegree = profile.releaseThreshold - 1;
    const shareLifting = profile.shareLifting;
    const shareRadix = 1n << BigInt(shareLifting.limbBits);
    // Roster position a evaluates at Z^a with Z = X^(degree/R).
    assert.equal(degree % interpolationRingDegree(participants), 0);
    const pointStride = degree / interpolationRingDegree(participants);
    const columns: Column[] = [],
        equations: Equation[] = [],
        supportRows: Row[] = [];
    const disjointPairs: [number, number][] = [];
    let randomState = seed;
    const random = () =>
        (randomState =
            (randomState * 6364136223846793005n + 1442695040888963407n) %
            (1n << 128n));
    const addColumn = (name: string, bits: number, kind: Column['kind']) => {
        const index = columns.length;
        columns.push({
            name,
            bits,
            kind,
            values: Array.from({ length: degree }, () => 0n),
        });
        return index;
    };
    const assign = (variable: Variable, values: readonly bigint[]) => {
        for (let position = 0; position < values.length; position++) {
            let encoded = values[position] - variable.offset;
            assert.ok(encoded >= 0n);
            for (const term of variable.terms) {
                const width = columns[term.column].bits;
                columns[term.column].values[position * variable.stride] =
                    encoded & ((1n << BigInt(width)) - 1n);
                encoded >>= BigInt(width);
            }
            assert.equal(encoded, 0n);
        }
    };
    const signed = (
        name: string,
        bits: number,
        values: readonly bigint[],
    ): Variable => {
        const terms: { column: number; factor: bigint }[] = [];
        let remaining = bits,
            shift = 0;
        while (remaining >= 16 || (shift === 0 && remaining > 0)) {
            const width = Math.min(16, remaining);
            terms.push({
                column: addColumn(
                    `${name}/word-${String(shift / 16)}`,
                    width,
                    'word',
                ),
                factor: 1n << BigInt(shift),
            });
            remaining -= width;
            shift += width;
        }
        while (remaining-- > 0) {
            terms.push({
                column: addColumn(`${name}/bit-${String(shift)}`, 1, 'boolean'),
                factor: 1n << BigInt(shift++),
            });
        }
        const variable = {
            terms,
            offset: -(1n << BigInt(bits - 1)),
            stride: degree / values.length,
        };
        assign(variable, values);
        return variable;
    };
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
    const sparse = (name: string, physicalDegree = degree) => {
        const positive = addColumn(`${name}/positive`, 1, 'boolean');
        const negative = addColumn(`${name}/negative`, 1, 'boolean');
        const variable: Variable = {
            terms: [
                { column: positive, factor: 1n },
                { column: negative, factor: -1n },
            ],
            offset: 0n,
            stride: degree / physicalDegree,
        };
        const values = Array.from({ length: physicalDegree }, () => 0n);
        let filled = 0;
        while (filled < 4) {
            const position = Number(random() % BigInt(physicalDegree));
            if (values[position] !== 0n) continue;
            values[position] = filled++ < 2 ? 1n : -1n;
        }
        for (let position = 0; position < physicalDegree; position++) {
            columns[positive].values[position * variable.stride] = BigInt(
                values[position] > 0n,
            );
            columns[negative].values[position * variable.stride] = BigInt(
                values[position] < 0n,
            );
        }
        disjointPairs.push([positive, negative]);
        for (const column of [positive, negative])
            supportRows.push({
                constant: -2n,
                terms: Array.from(
                    { length: physicalDegree },
                    (_value, position) => ({
                        column,
                        position: position * variable.stride,
                        factor: 1n,
                    }),
                ),
            });
        return { variable, values };
    };
    const secret = sparse('FHE secret'),
        auxiliary = sparse('FHE auxiliary secret');
    const shareEphemerals = Array.from(
        { length: participants },
        (_value, recipient) => sparse(`share encryption ${String(recipient)}`),
    );
    const sharingRadius = 1n << BigInt(shareLifting.sharingCoefficientBits - 1);
    const highRadius =
        1n <<
        BigInt(shareLifting.sharingCoefficientBits - shareLifting.limbBits - 1);
    const sharingValues = Array.from({ length: sharingDegree }, () =>
        Array.from({ length: degree }, (_unused, position) => {
            if (seed === 0n)
                return position % 2 === 0 ? -sharingRadius : sharingRadius - 1n;
            return (random() & (2n * sharingRadius - 1n)) - sharingRadius;
        }),
    );
    const sharing = sharingValues.map((values, index) => {
        const name = `sharing coefficient ${String(index + 1)}`;
        const encoded = values.map((value) => value + sharingRadius);
        return {
            low: signed(
                `${name}/low`,
                shareLifting.limbBits,
                encoded.map(
                    (value) => modulo(value, shareRadix) - shareRadix / 2n,
                ),
            ),
            high: signed(
                `${name}/high`,
                shareLifting.sharingCoefficientBits - shareLifting.limbBits,
                encoded.map((value) => value / shareRadix - highRadius),
            ),
        };
    });
    const publicPolynomial = (modulus: bigint, length = degree) =>
        Array.from({ length }, () => {
            let value = 0n;
            for (
                let offset = 0;
                offset < modulus.toString(2).length;
                offset += 128
            )
                value = (value << 128n) | random();
            return center(value, modulus);
        });
    const errors = (length = degree) =>
        Array.from({ length }, (_value, index) =>
            seed === 0n
                ? index % 2 === 0
                    ? -64n
                    : 63n
                : (random() & 127n) - 64n,
        );
    const evaluateRow = (row: Row) =>
        row.terms.reduce(
            (value, term) =>
                value +
                term.factor * columns[term.column].values[term.position],
            row.constant,
        );
    const compileEquation = (equation: Equation): Row[] => {
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
                            (position - index + equation.degree) %
                                equation.degree,
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
                                    (Math.floor(exponent / equation.degree) %
                                        2 ===
                                    0
                                        ? 1n
                                        : -1n) *
                                        digit(
                                            term.factor,
                                            limb,
                                            equation.radix,
                                        ),
                                );
                        }
                }
                for (const term of equation.shifts ?? []) {
                    const shift =
                        ((term.exponent % (2 * degree)) + 2 * degree) %
                        (2 * degree);
                    const input =
                        (((position - shift) % degree) + degree) % degree;
                    const sign =
                        Math.floor((input + shift) / degree) % 2 === 0
                            ? 1n
                            : -1n;
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
                if (limb > 0)
                    append(row, equation.carries[limb - 1], position, 1n);
                if (limb < equation.limbs - 1)
                    append(
                        row,
                        equation.carries[limb],
                        position,
                        -equation.radix,
                    );
                rows.push(row);
            }
        return rows;
    };
    const addEquation = (
        name: string,
        values: Omit<Equation, 'name' | 'quotient' | 'carries' | 'error'>,
        raw: readonly bigint[],
        errorValues: readonly bigint[],
        carryBits: number,
    ) => {
        const quotientValues = raw.map((value) => {
            assert.equal(value % values.modulus, 0n);
            return value / values.modulus;
        });
        const quotient = signed(`${name}/quotient`, 16, quotientValues);
        const carries = Array.from(
            { length: values.limbs - 1 },
            (_unused, limb) =>
                signed(
                    `${name}/carry-${String(limb)}`,
                    carryBits,
                    Array.from({ length: values.degree }, () => 0n),
                ),
        );
        const error = signed(`${name}/error`, 7, errorValues);
        const equation = { name, ...values, quotient, carries, error };
        for (let limb = 0; limb < carries.length; limb++) {
            const rows = compileEquation(equation).slice(
                limb * values.degree,
                (limb + 1) * values.degree,
            );
            assign(
                carries[limb],
                rows.map((row) => {
                    const value = evaluateRow(row);
                    assert.equal(value % values.radix, 0n);
                    return value / values.radix;
                }),
            );
        }
        assert.ok(
            compileEquation(equation).every((row) => evaluateRow(row) === 0n),
        );
        equations.push(equation);
    };
    const modulus = profile.ciphertext.modulus;
    const limbs = Math.ceil(modulus.toString(2).length / 96);
    for (
        let gadget = 1n, gadgetIndex = 0;
        gadget < modulus;
        gadget *= fixedModulusBfvInputs.gadgetBase, gadgetIndex++
    ) {
        const commonEncryption = publicPolynomial(modulus);
        for (const kind of [
            'encryption',
            'first relinearization',
            'second relinearization',
            'automorphism',
        ] as const) {
            const common =
                kind === 'encryption' || kind === 'first relinearization'
                    ? commonEncryption
                    : publicPolynomial(modulus);
            const error = errors();
            const left = kind === 'first relinearization' ? auxiliary : secret;
            const right =
                kind === 'first relinearization' || kind === 'automorphism'
                    ? secret
                    : auxiliary;
            const multiplier =
                kind === 'encryption'
                    ? 0n
                    : kind === 'second relinearization'
                      ? -gadget
                      : gadget;
            const transformed = right.values.map(() => 0n);
            right.values.forEach((value, position) => {
                const exponent = position * (kind === 'automorphism' ? 5 : 1);
                transformed[exponent % degree] +=
                    (Math.floor(exponent / degree) % 2 === 0 ? 1n : -1n) *
                    value;
            });
            const product = convolution(common, left.values);
            const publicValue = product.map((value, position) =>
                center(
                    -value +
                        multiplier * transformed[position] +
                        error[position],
                    modulus,
                ),
            );
            const raw = product.map(
                (value, position) =>
                    value +
                    publicValue[position] -
                    multiplier * transformed[position] -
                    error[position],
            );
            addEquation(
                `${kind}/${String(gadgetIndex)}`,
                {
                    modulus,
                    degree,
                    publicValue,
                    publicSign: 1n,
                    convolution: [
                        { publicCoefficients: common, variable: left.variable },
                    ],
                    direct:
                        multiplier === 0n
                            ? []
                            : [
                                  {
                                      variable: right.variable,
                                      factor: -multiplier,
                                      ...(kind === 'automorphism'
                                          ? { automorphism: 5 }
                                          : {}),
                                  },
                              ],
                    errorSign: -1n,
                    limbs,
                    radix: fheRadix,
                },
                raw,
                error,
                16,
            );
        }
    }
    const decryptedShares: bigint[][] = [],
        expectedShares: bigint[][] = [];
    const commonShare = publicPolynomial(shareModulus);
    for (let recipient = 0; recipient < participants; recipient++) {
        const recipientSecret = Array.from(
            { length: degree },
            (_value, index) => (index < 4 ? (index < 2 ? 1n : -1n) : 0n),
        );
        const recipientError = errors();
        const publicKey = convolution(commonShare, recipientSecret).map(
            (value, position) =>
                center(-value + recipientError[position], shareModulus),
        );
        const point = Array.from({ length: degree }, () => 0n);
        const pointExponent = recipient * pointStride;
        point[pointExponent % degree] =
            Math.floor(pointExponent / degree) % 2 === 0 ? 1n : -1n;
        let power = Array.from({ length: degree }, (_value, index) =>
            BigInt(index === 0),
        );
        let message = [...secret.values];
        for (const coefficient of sharingValues) {
            power = convolution(power, point);
            message = addPolynomials(message, convolution(coefficient, power));
        }
        const offset = Array.from({ length: degree }, () => 0n);
        for (let coefficient = 0; coefficient < sharingDegree; coefficient++) {
            const exponent = pointExponent * (coefficient + 1);
            for (let position = 0; position < degree; position++) {
                const shifted = position + exponent;
                offset[shifted % degree] +=
                    (Math.floor(shifted / degree) % 2 === 0 ? 1n : -1n) *
                    shareScale *
                    (shareRadix / 2n);
            }
        }
        const ephemeral = shareEphemerals[recipient];
        const error0 = errors(),
            error1 = errors();
        const product0 = convolution(publicKey, ephemeral.values),
            product1 = convolution(commonShare, ephemeral.values);
        const first = product0.map((value, position) =>
            center(
                value + shareScale * message[position] + error0[position],
                shareModulus,
            ),
        );
        const second = product1.map((value, position) =>
            center(value + error1[position], shareModulus),
        );
        addEquation(
            `encrypted-share-${String(recipient)}/constant`,
            {
                modulus: shareModulus,
                degree,
                publicValue: first,
                publicSign: -1n,
                convolution: [
                    {
                        publicCoefficients: publicKey,
                        variable: ephemeral.variable,
                    },
                ],
                direct: [{ variable: secret.variable, factor: shareScale }],
                shifts: sharing.map(({ low, high }, index) => ({
                    low,
                    high,
                    exponent: pointExponent * (index + 1),
                    factor: shareScale,
                })),
                offset,
                errorSign: 1n,
                limbs: 2,
                radix: shareRadix,
            },
            product0.map(
                (value, position) =>
                    value +
                    shareScale * message[position] +
                    error0[position] -
                    first[position],
            ),
            error0,
            shareLifting.carryBits,
        );
        addEquation(
            `encrypted-share-${String(recipient)}/linear`,
            {
                modulus: shareModulus,
                degree,
                publicValue: second,
                publicSign: -1n,
                convolution: [
                    {
                        publicCoefficients: commonShare,
                        variable: ephemeral.variable,
                    },
                ],
                direct: [],
                errorSign: 1n,
                limbs: 2,
                radix: shareRadix,
            },
            product1.map(
                (value, position) =>
                    value + error1[position] - second[position],
            ),
            error1,
            16,
        );
        const phase = addPolynomials(
            first,
            convolution(second, recipientSecret),
        ).map((value) => center(value, shareModulus));
        const recovered = phase.map((value) => {
            const magnitude = value < 0n ? -value : value;
            const rounded = (magnitude + shareScale / 2n) / shareScale;
            return value < 0n ? -rounded : rounded;
        });
        decryptedShares.push(recovered);
        expectedShares.push(message);
    }
    const rows = () => [...equations.flatMap(compileEquation), ...supportRows];
    const transpose = (alpha: bigint) => {
        alpha = modulo(alpha, prime);
        const coefficients = columns.map(() =>
            Array.from({ length: degree }, () => 0n),
        );
        let constant = 0n,
            prefix = 1n;
        const powers = [1n];
        for (let position = 1; position <= degree * limbs; position++)
            powers.push((powers[position - 1] * alpha) % prime);
        const addVariable = (
            variable: Variable,
            weights: readonly bigint[],
        ) => {
            weights.forEach((weight, position) => {
                constant = modulo(constant + variable.offset * weight, prime);
                for (const term of variable.terms) {
                    const index = position * variable.stride;
                    coefficients[term.column][index] = modulo(
                        coefficients[term.column][index] + term.factor * weight,
                        prime,
                    );
                }
            });
        };
        for (const equation of equations) {
            const positions = powers.slice(0, equation.degree);
            const fingerprint = (value: bigint) =>
                fingerprintSignedLimbs(
                    value,
                    equation.radix,
                    equation.limbs,
                    powers[equation.degree],
                    prime,
                );
            for (let position = 0; position < equation.degree; position++)
                constant = modulo(
                    constant +
                        prefix *
                            positions[position] *
                            (equation.publicSign *
                                fingerprint(equation.publicValue[position]) +
                                fingerprint(equation.offset?.[position] ?? 0n)),
                    prime,
                );
            for (const term of equation.convolution)
                addVariable(
                    term.variable,
                    geometricNegacyclicAdjoint(
                        term.publicCoefficients.map(fingerprint),
                        alpha,
                        prime,
                    ).map((value) => (value * prefix) % prime),
                );
            for (const term of equation.direct)
                addVariable(
                    term.variable,
                    positions.map((_value, input) => {
                        const exponent = input * (term.automorphism ?? 1);
                        return (
                            (prefix *
                                fingerprint(term.factor) *
                                positions[exponent % equation.degree] *
                                (Math.floor(exponent / equation.degree) % 2 ===
                                0
                                    ? 1n
                                    : -1n)) %
                            prime
                        );
                    }),
                );
            for (const term of equation.shifts ?? []) {
                const monomialWeights = positions.map((_value, input) => {
                    const exponent = input + term.exponent;
                    return (
                        (prefix *
                            term.factor *
                            positions[exponent % equation.degree] *
                            (Math.floor(exponent / equation.degree) % 2 === 0
                                ? 1n
                                : -1n)) %
                        prime
                    );
                });
                addVariable(term.low, monomialWeights);
                addVariable(
                    term.high,
                    monomialWeights.map(
                        (value) => (value * powers[equation.degree]) % prime,
                    ),
                );
            }
            addVariable(
                equation.error,
                positions.map(
                    (value) => (value * prefix * equation.errorSign) % prime,
                ),
            );
            addVariable(
                equation.quotient,
                positions.map(
                    (value) =>
                        (-value * prefix * fingerprint(equation.modulus)) %
                        prime,
                ),
            );
            equation.carries.forEach((carry, limb) =>
                addVariable(
                    carry,
                    positions.map(
                        (value) =>
                            (value *
                                prefix *
                                (powers[(limb + 1) * equation.degree] -
                                    equation.radix *
                                        powers[limb * equation.degree])) %
                            prime,
                    ),
                ),
            );
            prefix =
                (prefix * powers[equation.degree * equation.limbs]) % prime;
        }
        for (const row of supportRows) {
            constant = modulo(constant + prefix * row.constant, prime);
            for (const term of row.terms)
                coefficients[term.column][term.position] = modulo(
                    coefficients[term.column][term.position] +
                        prefix * term.factor,
                    prime,
                );
            prefix = (prefix * alpha) % prime;
        }
        return { coefficients, target: modulo(-constant, prime) };
    };
    const verify = () =>
        equations.every((equation) =>
            [
                equation.publicValue,
                ...equation.convolution.map((term) => term.publicCoefficients),
            ].every((coefficients) =>
                isCanonicalCenteredPolynomial(
                    coefficients,
                    equation.degree,
                    equation.modulus,
                ),
            ),
        ) &&
        columns.every((column) =>
            column.values.every(
                (value) => value >= 0n && value < 1n << BigInt(column.bits),
            ),
        ) &&
        disjointPairs.every(([positive, negative]) =>
            columns[positive].values.every(
                (value, position) =>
                    value * columns[negative].values[position] === 0n,
            ),
        ) &&
        rows().every((row) => modulo(evaluateRow(row), prime) === 0n);
    return {
        degree,
        columns,
        disjointPairs,
        equations,
        rows,
        transpose,
        evaluateRow,
        verify,
        decryptedShares,
        expectedShares,
    };
};

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
    const variableBits = [
        // FHE key equations: quotient, carries and error.
        ...Array.from({ length: fheEquations }, () => [
            16,
            ...Array.from({ length: fheLimbs - 1 }, () => 16),
            7,
        ]).flat(),
        // Sharing coefficients: low and high limb parts.
        ...Array.from({ length: sharingDegree }, () => [
            limbBits,
            sharingCoefficientBits - limbBits,
        ]).flat(),
        // Each recipient's constant and linear share equations.
        ...Array.from({ length: participants }, () => [
            16,
            carryBits,
            7,
            16,
            16,
            7,
        ]).flat(),
    ];
    const columns = variableBits.map(signedVariableColumns);
    // The FHE secret, FHE auxiliary secret and recipient ephemerals each
    // have a positive and a negative column.
    const disjointPairs = participants + 2;
    const wordColumns = columns.reduce((sum, value) => sum + value.words, 0);
    const narrowWords = columns.reduce(
        (sum, value) => sum + value.narrowWords,
        0,
    );
    const booleanColumns =
        2 * disjointPairs +
        columns.reduce((sum, value) => sum + value.booleans, 0);
    const supportRows = 2 * disjointPairs;
    return {
        wordColumns,
        booleanColumns,
        errorColumns: variableBits.filter((bits) => bits === 7).length,
        disjointPairs,
        supportRows,
        lookupEntries: wordColumns + narrowWords,
        affineRows:
            BigInt(fheEquations * fheLimbs + 4 * participants) *
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
        4n +
        4n +
        publicCoefficientMagnitudeByteLength +
        shareMagnitudeByteLength;
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
            fheStatementPolynomials + sharingStatementPolynomials,
        expandedStatementHeaderByteLength,
        expandedStatementByteLength:
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
