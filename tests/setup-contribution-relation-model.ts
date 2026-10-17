import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { isCanonicalCenteredPolynomial } from '#tests/canonical-polynomial-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    type Column,
    type Variable,
    type Row,
    type Equation,
    fheRadix,
    setupEquationWidths,
    prime,
    modulo,
    compileSetupEquation,
} from '#tests/setup-relation/equations.js';
import { transposeSetupRelation } from '#tests/setup-relation/transpose.js';
import {
    interpolationRingDegree,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

const shareScale = shareEncryptionParameters.scale;

export const shareModulus = shareEncryptionParameters.modulus;

const center = (value: bigint, modulus: bigint) => {
    const result = modulo(value, modulus);
    return result > modulus / 2n ? result - modulus : result;
};

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
        const quotient = signed(
            `${name}/quotient`,
            setupEquationWidths.quotientBits,
            quotientValues,
        );
        const carries = Array.from(
            { length: values.limbs - 1 },
            (_unused, limb) =>
                signed(
                    `${name}/carry-${String(limb)}`,
                    carryBits,
                    Array.from({ length: values.degree }, () => 0n),
                ),
        );
        const error = signed(
            `${name}/error`,
            setupEquationWidths.errorBits,
            errorValues,
        );
        const equation = { name, ...values, quotient, carries, error };
        for (let limb = 0; limb < carries.length; limb++) {
            const rows = compileSetupEquation(equation, degree).slice(
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
            compileSetupEquation(equation, degree).every(
                (row) => evaluateRow(row) === 0n,
            ),
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
                setupEquationWidths.fheCarryBits,
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
            setupEquationWidths.fheCarryBits,
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
    const baseEquationCount = equations.length;
    const baseSupportCount = supportRows.length;
    const sourceEphemeral = sparse('source encryption', degree / 2);
    // Honest sampling embeds the auxiliary ring. The relation's support
    // sums range over the full ambient columns, including hostile positions.
    for (const row of supportRows.slice(baseSupportCount)) {
        const column = row.terms[0].column;
        row.terms = Array.from({ length: degree }, (_unused, position) => ({
            column,
            position,
            factor: 1n,
        }));
    }
    const sourceVariable = { ...sourceEphemeral.variable, stride: 1 };
    const sourceValues = Array.from({ length: degree }, (_unused, index) =>
        index % 2 === 0 ? sourceEphemeral.values[index / 2] : 0n,
    );
    const originalError = equations[0].error;
    const readVariable = (variable: Variable, position: number) =>
        variable.terms.reduce(
            (value, term) =>
                value +
                term.factor *
                    columns[term.column].values[position * variable.stride],
            variable.offset,
        );
    const sourceModulus = auxiliaryInputEncryptionParameters.modulus;
    const sourceScale = auxiliaryInputEncryptionParameters.scale;
    for (let component = 0; component < 4; component++) {
        const common = publicPolynomial(sourceModulus);
        const error = errors();
        const message = Array.from({ length: degree }, (_unused, position) =>
            component === 0
                ? secret.values[position] + 1n
                : component === 2
                  ? readVariable(originalError, position) + 64n
                  : 0n,
        );
        const product = convolution(common, sourceValues);
        const raw = product.map(
            (value, position) =>
                value + sourceScale * message[position] + error[position],
        );
        const ciphertext = raw.map((value) => center(value, sourceModulus));
        addEquation(
            `encrypted-source-${component}`,
            {
                modulus: sourceModulus,
                degree,
                publicValue: ciphertext,
                publicSign: -1n,
                convolution: [
                    { publicCoefficients: common, variable: sourceVariable },
                ],
                direct:
                    component === 0
                        ? [{ variable: secret.variable, factor: sourceScale }]
                        : component === 2
                          ? [{ variable: originalError, factor: sourceScale }]
                          : [],
                offset: Array.from({ length: degree }, () =>
                    component === 0
                        ? sourceScale
                        : component === 2
                          ? 64n * sourceScale
                          : 0n,
                ),
                errorSign: 1n,
                limbs: 1,
                radix: fheRadix,
            },
            raw.map((value, position) => value - ciphertext[position]),
            error,
            setupEquationWidths.fheCarryBits,
        );
    }
    const appendedSourceRows = () => [
        ...equations
            .slice(baseEquationCount)
            .flatMap((equation) => compileSetupEquation(equation, degree)),
        ...supportRows.slice(baseSupportCount),
    ];
    const rows = () => [
        ...equations
            .slice(0, baseEquationCount)
            .flatMap((equation) => compileSetupEquation(equation, degree)),
        ...supportRows.slice(0, baseSupportCount),
        ...appendedSourceRows(),
    ];
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
        transpose: (alpha: bigint) =>
            transposeSetupRelation(
                {
                    degree,
                    limbs,
                    columns,
                    equations: equations.slice(0, baseEquationCount),
                    supportRows: [
                        ...supportRows.slice(0, baseSupportCount),
                        ...appendedSourceRows(),
                    ],
                },
                alpha,
            ),
        evaluateRow,
        verify,
        decryptedShares,
        expectedShares,
        sourceEquations: equations.slice(baseEquationCount),
        sourceEphemeral: sourceVariable,
    };
};
