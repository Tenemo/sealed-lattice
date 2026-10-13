import {
    fingerprintSignedLimbs,
    geometricNegacyclicAdjoint,
} from '#tests/geometric-ring-adjoint-model.js';
import {
    type Column,
    type Variable,
    type Row,
    type Equation,
    prime,
    modulo,
} from '#tests/setup-relation/equations.js';

export const transposeSetupRelation = (
    system: Readonly<{
        degree: number;
        limbs: number;
        columns: readonly Column[];
        equations: readonly Equation[];
        supportRows: readonly Row[];
    }>,
    alpha: bigint,
) => {
    const { degree, limbs, columns, equations, supportRows } = system;

    alpha = modulo(alpha, prime);
    const coefficients = columns.map(() =>
        Array.from({ length: degree }, () => 0n),
    );
    let constant = 0n,
        prefix = 1n;
    const powers = [1n];
    for (let position = 1; position <= degree * limbs; position++)
        powers.push((powers[position - 1] * alpha) % prime);
    const addVariable = (variable: Variable, weights: readonly bigint[]) => {
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
                            (Math.floor(exponent / equation.degree) % 2 === 0
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
                    (-value * prefix * fingerprint(equation.modulus)) % prime,
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
        prefix = (prefix * powers[equation.degree * equation.limbs]) % prime;
    }
    for (const row of supportRows) {
        constant = modulo(constant + prefix * row.constant, prime);
        for (const term of row.terms)
            coefficients[term.column][term.position] = modulo(
                coefficients[term.column][term.position] + prefix * term.factor,
                prime,
            );
        prefix = (prefix * alpha) % prime;
    }
    return { coefficients, target: modulo(-constant, prime) };
};
