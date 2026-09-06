import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { isCanonicalCenteredPolynomial } from '#tests/canonical-polynomial-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    fingerprintSignedLimbs,
    geometricNegacyclicAdjoint,
} from '#tests/geometric-ring-adjoint-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

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
type MonomialTerm = Readonly<{
    variable: Variable;
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
}>;

const radix = 1n << 96n;
const prime = compileSmallLimbProofFieldCensus().modulus;
const sharingParameters = compileWideShareLiftingCensus();
const shareScale = sharingParameters.scale;
const shareModulus = sharingParameters.modulus;
const auxiliaryModulus = auxiliaryInputEncryptionParameters.modulus;
const modulo = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;
const center = (value: bigint, modulus: bigint) => {
    const result = modulo(value, modulus);
    return result > modulus / 2n ? result - modulus : result;
};
const digit = (value: bigint, limb: number) =>
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
export const createSetupContributionRelationModel = (seed = 1n) => {
    const degree = 16,
        auxiliaryDegree = 8;
    const participants = Number(fixedModulusBfvInputs.participantCount);
    const sharingDegree = Math.floor((participants - 1) / 3);
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
    const auxiliarySecret = sparse(
        'auxiliary encryption secret',
        auxiliaryDegree,
    );
    const sharingValues = Array.from({ length: sharingDegree }, () =>
        Array.from({ length: degree }, (_unused, position) => {
            const radius =
                1n << BigInt(sharingParameters.sharingCoefficientBits - 1);
            if (seed === 0n) return position % 2 === 0 ? -radius : radius - 1n;
            return (random() & (2n * radius - 1n)) - radius;
        }),
    );
    const sharing = sharingValues.map((values, index) =>
        signed(
            `sharing coefficient ${String(index + 1)}`,
            sharingParameters.sharingCoefficientBits,
            values,
        ),
    );
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
                            digit(equation.publicValue[position], limb) +
                        digit(equation.offset?.[position] ?? 0n, limb),
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
                                digit(term.publicCoefficients[index], limb),
                        );
                for (const term of equation.direct) {
                    if (term.automorphism === undefined)
                        append(
                            row,
                            term.variable,
                            position,
                            digit(term.factor, limb),
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
                                        : -1n) * digit(term.factor, limb),
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
                    const variable =
                        limb === 0
                            ? {
                                  terms: term.variable.terms.slice(0, 6),
                                  offset: -(radix / 2n),
                                  stride: 1,
                              }
                            : {
                                  terms: term.variable.terms
                                      .slice(6)
                                      .map((value) => ({
                                          ...value,
                                          factor: value.factor / radix,
                                      })),
                                  offset: -(
                                      1n <<
                                      BigInt(
                                          sharingParameters.sharingCoefficientBits -
                                              96 -
                                              1,
                                      )
                                  ),
                                  stride: 1,
                              };
                    append(row, variable, input, sign * term.factor);
                }
                if (limb === 0)
                    append(row, equation.error, position, equation.errorSign);
                append(
                    row,
                    equation.quotient,
                    position,
                    -digit(equation.modulus, limb),
                );
                if (limb > 0)
                    append(row, equation.carries[limb - 1], position, 1n);
                if (limb < equation.limbs - 1)
                    append(row, equation.carries[limb], position, -radix);
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
                    assert.equal(value % radix, 0n);
                    return value / radix;
                }),
            );
        }
        assert.ok(
            compileEquation(equation).every((row) => evaluateRow(row) === 0n),
        );
        equations.push(equation);
    };
    const modulus = fixedModulusBfvInputs.ciphertextModulus;
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
        const pointExponent = (recipient * degree) / 8;
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
                    (radix / 2n);
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
                shifts: sharing.map((variable, index) => ({
                    variable,
                    exponent: pointExponent * (index + 1),
                    factor: shareScale,
                })),
                offset,
                errorSign: 1n,
                limbs: 2,
            },
            product0.map(
                (value, position) =>
                    value +
                    shareScale * message[position] +
                    error0[position] -
                    first[position],
            ),
            error0,
            32,
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
    const auxiliaryCommon = publicPolynomial(auxiliaryModulus, auxiliaryDegree),
        auxiliaryError = errors(auxiliaryDegree);
    const auxiliaryProduct = convolution(
        auxiliaryCommon,
        auxiliarySecret.values,
    );
    const auxiliaryPublic = auxiliaryProduct.map((value, position) =>
        center(-value + auxiliaryError[position], auxiliaryModulus),
    );
    addEquation(
        'auxiliary public key',
        {
            modulus: auxiliaryModulus,
            degree: auxiliaryDegree,
            publicValue: auxiliaryPublic,
            publicSign: 1n,
            convolution: [
                {
                    publicCoefficients: auxiliaryCommon,
                    variable: auxiliarySecret.variable,
                },
            ],
            direct: [],
            errorSign: -1n,
            limbs: 1,
        },
        auxiliaryProduct.map(
            (value, position) =>
                value + auxiliaryPublic[position] - auxiliaryError[position],
        ),
        auxiliaryError,
        16,
    );
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
                    radix,
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
                const low = {
                    terms: term.variable.terms.slice(0, 6),
                    offset: -radix / 2n,
                    stride: 1,
                };
                const high = {
                    terms: term.variable.terms.slice(6).map((value) => ({
                        ...value,
                        factor: value.factor / radix,
                    })),
                    offset: -(
                        1n <<
                        BigInt(
                            sharingParameters.sharingCoefficientBits - 96 - 1,
                        )
                    ),
                    stride: 1,
                };
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
                addVariable(low, monomialWeights);
                addVariable(
                    high,
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
                                    radix * powers[limb * equation.degree])) %
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
        auxiliaryDegree,
        columns,
        equations,
        rows,
        transpose,
        evaluateRow,
        verify,
        decryptedShares,
        expectedShares,
        auxiliarySecretColumns: auxiliarySecret.variable.terms.map(
            ({ column }) => column,
        ),
    };
};

export const compileSetupContributionRelationCensus = () => {
    const model = createSetupContributionRelationModel();
    const wordColumns = model.columns.filter(
        ({ kind }) => kind === 'word',
    ).length;
    const booleanColumns = model.columns.length - wordColumns;
    const errorColumns = model.columns.filter(({ bits }) => bits === 7).length;
    const disjointPairs = model.columns.filter(({ name }) =>
        name.endsWith('/positive'),
    ).length;
    const supportRows = 2 * disjointPairs;
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const auxiliaryDegree = auxiliaryInputEncryptionParameters.degree;
    const field = compileSmallLimbProofFieldCensus();
    const extensionElementByteLength = field.packedExtensionElementByteLength;
    const agreement = compileCommonAgreementDegreeCensus();
    const maximumPublicQueryCount = 2 * agreement.queries;
    const publicQueryValueByteLength =
        BigInt(maximumPublicQueryCount) * extensionElementByteLength;
    const singlePublicAdjointCoefficientByteLength =
        degree * extensionElementByteLength;
    const publicCoefficientMagnitudeByteLength =
        BigInt(fixedModulusBfvInputs.ciphertextModulus.toString(2).length + 7) /
        8n;
    const affineRows = model.equations.reduce(
        (sum, equation) =>
            sum +
            BigInt(equation.limbs) *
                (equation.degree === model.auxiliaryDegree
                    ? auxiliaryDegree
                    : degree),
        BigInt(supportRows),
    );
    return {
        wordColumns,
        booleanColumns,
        errorColumns,
        disjointPairs,
        supportRows,
        affineRows,
        lookupEntries: wordColumns + errorColumns,
        fullAffineCoefficientByteLength:
            BigInt(model.columns.length) *
            singlePublicAdjointCoefficientByteLength,
        singlePublicAdjointCoefficientByteLength,
        largestPublicPolynomialByteLength:
            degree * (1n + publicCoefficientMagnitudeByteLength),
        maximumPublicQueryCount,
        publicQueryValueByteLength,
        fullAffineQueryValueByteLength:
            BigInt(model.columns.length) * publicQueryValueByteLength,
        publicQueryTransformVectorByteLength:
            2n * singlePublicAdjointCoefficientByteLength +
            (degree / 2n) * field.packedFieldElementByteLength +
            publicQueryValueByteLength,
        fullRingQueryCosets: BigInt(agreement.domainSize) / degree,
        auxiliaryQueryCosets: BigInt(agreement.domainSize) / auxiliaryDegree,
    };
};
