import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { isCanonicalCenteredPolynomial } from '#tests/canonical-polynomial-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const proofPrime = compileSmallLimbProofFieldCensus().modulus;
const plaintextModulus = fixedModulusBfvInputs.plaintextModulus;
const modulus = fixedModulusBfvInputs.ciphertextModulus;
const radix = 1n << 96n;
const scale = (modulus + plaintextModulus / 2n) / plaintextModulus;
const auxiliary = auxiliaryInputEncryptionParameters;
const modulo = (value: bigint, target: bigint) =>
    ((value % target) + target) % target;
const centered = (value: bigint, target: bigint) => {
    const reduced = modulo(value, target);
    return reduced > target / 2n ? reduced - target : reduced;
};
const signedRange = (value: bigint, bits: number) =>
    value >= -(1n << BigInt(bits - 1)) && value < 1n << BigInt(bits - 1);
const digit = (value: bigint, index: number) =>
    (value < 0n ? -1n : 1n) *
    (((value < 0n ? -value : value) / radix ** BigInt(index)) % radix);

export const compileBallotEncryptionRelationCensus = () => {
    const participants = fixedModulusBfvInputs.participantCount;
    const support = fixedModulusBfvInputs.secretSupportWeight;
    const error = fixedModulusBfvInputs.errorBound;
    const limbs = Math.ceil(modulus.toString(2).length / 96);
    const plaintextBound = plaintextModulus / 2n;
    const quotientBound = 1n << 15n,
        carryBound = 1n << 15n;
    const trueQuotientBound =
        ((support + 1n) * (modulus / 2n) + scale * plaintextBound + error) /
        modulus;
    // The current scale occupies only the final public radix limb. Earlier
    // carry recurrences therefore contain no large plaintext product.
    assert.equal(scale % radix ** BigInt(limbs - 1), 0n);
    const trueCarryBound = support + trueQuotientBound + 3n;
    const residualBound =
        (support + quotientBound + plaintextBound + 2n) * (radix - 1n) +
        error +
        carryBound * (radix + 1n);
    const auxiliaryNoiseBound =
        (2n * participants * auxiliary.support + 1n) * error;
    assert.equal(
        auxiliary.modulus,
        auxiliary.plaintextModulus * auxiliary.scale + 1n,
    );
    assert.ok(2n * auxiliaryNoiseBound < auxiliary.scale);
    assert.ok(trueQuotientBound < quotientBound);
    assert.ok(trueCarryBound < carryBound);
    assert.ok(residualBound < proofPrime);
    const packingQuotientBound =
        (BigInt(fixedModulusBfvInputs.optionCount) * 10n * plaintextBound +
            plaintextBound) /
        plaintextModulus;
    const packingResidualBound =
        plaintextBound *
            (1n + 10n * BigInt(fixedModulusBfvInputs.optionCount)) +
        plaintextModulus * quotientBound;
    const auxiliaryResidualBound =
        (auxiliary.support + 1n) * (auxiliary.modulus / 2n) +
        10n * auxiliary.scale +
        error +
        auxiliary.modulus * quotientBound;
    assert.ok(packingResidualBound < proofPrime);
    assert.ok(auxiliaryResidualBound < proofPrime);
    const wordColumns = 2 * (1 + limbs - 1 + 1) + 3 + 4;
    return {
        limbs,
        scale,
        trueQuotientBound,
        trueCarryBound,
        residualBound,
        auxiliaryNoiseBound,
        packingQuotientBound,
        packingResidualBound,
        auxiliaryResidualBound,
        wordColumns,
        booleanColumns: 5,
        additionalQuadraticConstraints: 3,
        narrowMemberships: 5,
        lookupEntries: wordColumns + 5,
        affineRows:
            BigInt(2 * limbs + 1) * fixedModulusBfvInputs.polynomialDegree +
            2n * auxiliary.degree +
            4n,
    };
};

const fieldModulus = Number(plaintextModulus);
const fieldReduce = (value: number) =>
    ((value % fieldModulus) + fieldModulus) % fieldModulus;
const fieldPower = (value: number, exponent: number) => {
    let result = 1;
    for (; exponent > 0; exponent = Math.floor(exponent / 2)) {
        if (exponent % 2 === 1) result = fieldReduce(result * value);
        value = fieldReduce(value * value);
    }
    return result;
};
const inverseTransform = (values: number[], root: number) => {
    const degree = values.length;
    root = fieldPower(root, fieldModulus - 2);
    for (let index = 0; index < degree; index++) {
        let reversed = 0,
            remaining = index;
        for (let bit = 0; bit < Math.log2(degree); bit++) {
            reversed = 2 * reversed + (remaining % 2);
            remaining = Math.floor(remaining / 2);
        }
        if (index < reversed)
            [values[index], values[reversed]] = [
                values[reversed],
                values[index],
            ];
    }
    for (let width = 2; width <= degree; width *= 2) {
        const step = fieldPower(root, degree / width);
        for (let start = 0; start < degree; start += width) {
            let twiddle = 1;
            for (let index = 0; index < width / 2; index++) {
                const first = values[start + index],
                    second = fieldReduce(
                        values[start + index + width / 2] * twiddle,
                    );
                values[start + index] = fieldReduce(first + second);
                values[start + index + width / 2] = fieldReduce(first - second);
                twiddle = fieldReduce(twiddle * step);
            }
        }
    }
    const inverseDegree = fieldPower(degree, fieldModulus - 2);
    return values.map((value) => fieldReduce(value * inverseDegree));
};

const packingMatrix = (
    degree: number,
    optionCount: number,
    topCount: number,
) => {
    const window = 2 ** Math.ceil(Math.log2(optionCount));
    const activeSlots = optionCount * topCount * window;
    assert.ok(activeSlots + optionCount < degree / 4);
    const root = fieldPower(3, (fieldModulus - 1) / degree);
    const orbit = Array.from({ length: degree / 4 }, () => 0);
    let exponent = 1;
    for (let index = 0; index < orbit.length; index++) {
        orbit[index] = exponent;
        exponent = (exponent * 5) % degree;
    }
    const columns = Array.from({ length: optionCount }, (_unused, selected) => {
        const slots = Array.from({ length: degree / 4 }, () => 0);
        for (let option = 0; option < optionCount; option++)
            for (let rank = 0; rank < topCount; rank++)
                for (let opponent = 0; opponent < optionCount; opponent++)
                    slots[(option * topCount + rank) * window + opponent] =
                        2 * Number(opponent === selected) -
                        2 * Number(option === selected);
        slots[activeSlots + selected] = 1;
        const natural = Array.from({ length: degree / 2 }, () => 0);
        orbit.forEach(
            (value, index) =>
                (natural[(value - 1) / 2] = fieldReduce(slots[index])),
        );
        const transformed = inverseTransform(natural, fieldReduce(root * root));
        const result = Array.from({ length: degree }, () => 0n);
        const inverseRoot = fieldPower(root, fieldModulus - 2);
        let twist = 1;
        transformed.forEach((value, index) => {
            result[2 * index] = centered(
                BigInt(fieldReduce(value * twist)),
                plaintextModulus,
            );
            twist = fieldReduce(twist * inverseRoot);
        });
        return result;
    });
    return { columns, root, orbit, activeSlots, window };
};

const convolution = (left: readonly bigint[], right: readonly bigint[]) => {
    const degree = left.length;
    assert.equal(right.length, degree);
    const result = Array.from({ length: degree }, () => 0n);
    left.forEach((value, first) =>
        right.forEach(
            (other, second) =>
                (result[(first + second) % degree] +=
                    value * other * (first + second >= degree ? -1n : 1n)),
        ),
    );
    return result;
};
const rowProduct = (
    left: readonly bigint[],
    right: readonly bigint[],
    row: number,
) =>
    left.reduce(
        (sum, value, index) =>
            sum +
            value *
                right[(row - index + left.length) % left.length] *
                (row < index ? -1n : 1n),
        0n,
    );

// Reduced physical rings and sparse supports; current moduli and all distinct
// packing, range, quotient, carry, and linked-encryption families are retained.
export const createBallotEncryptionRelationModel = (
    scores: readonly bigint[],
    auxiliaryScores: readonly bigint[] = scores,
) => {
    assert.equal(scores.length, 2);
    assert.equal(auxiliaryScores.length, scores.length);
    const degree = 64,
        auxiliaryDegree = 8;
    const packing = packingMatrix(degree, scores.length, scores.length);
    const scoreWords = scores.map((score) => score - 1n);
    const integerPlaintext = Array.from(
        { length: degree },
        (_unused, position) =>
            packing.columns.reduce(
                (sum, column, index) => sum + column[position] * scores[index],
                0n,
            ),
    );
    const plaintext = integerPlaintext.map((value) =>
        centered(value, plaintextModulus),
    );
    const plaintextWords = plaintext.map((value) => (value + 32768n) % 65536n);
    const plaintextHighBits = plaintext.map(
        (value) => (value + 32768n) / 65536n,
    );
    const packingQuotient = plaintext.map(
        (value, index) => (value - integerPlaintext[index]) / plaintextModulus,
    );
    let state = 1n;
    const random = () =>
        (state =
            (state * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 1024n) - 1n));
    const sparse = (length: number, aggregate: boolean) =>
        Array.from({ length }, (_unused, index) =>
            index < 4 ? (index < 2 ? 1n : -1n) * (aggregate ? 10n : 1n) : 0n,
        );
    const error = (length: number, negative: boolean) =>
        Array.from({ length }, () => (negative ? -64n : 63n));
    const makeEncryption = (
        length: number,
        ciphertextModulus: bigint,
        plaintextScale: bigint,
        message: readonly bigint[],
    ) => {
        const secret = sparse(length, true),
            ephemeral = sparse(length, false);
        const common = Array.from({ length }, () =>
            centered(random(), ciphertextModulus),
        );
        const publicKey = convolution(common, secret).map((value) =>
            centered(-value - 640n, ciphertextModulus),
        );
        const errors = [error(length, false), error(length, true)];
        const products = [
            convolution(publicKey, ephemeral),
            convolution(common, ephemeral),
        ];
        const raw = products.map((values, component) =>
            values.map(
                (value, position) =>
                    value +
                    errors[component][position] +
                    (component === 0 ? plaintextScale * message[position] : 0n),
            ),
        );
        const ciphertext = raw.map((values) =>
            values.map((value) => centered(value, ciphertextModulus)),
        );
        const quotients = raw.map((values, component) =>
            values.map(
                (value, position) =>
                    (value - ciphertext[component][position]) /
                    ciphertextModulus,
            ),
        );
        const phase = convolution(ciphertext[1], secret).map(
            (value, position) =>
                centered(value + ciphertext[0][position], ciphertextModulus),
        );
        const decoded = phase.map((value) => {
            const absolute = value < 0n ? -value : value;
            const rounded = (absolute + plaintextScale / 2n) / plaintextScale;
            return value < 0n ? -rounded : rounded;
        });
        return {
            common,
            publicKey,
            secret,
            ephemeral,
            errors,
            ciphertext,
            quotients,
            decoded,
        };
    };
    const fhe = makeEncryption(degree, modulus, scale, plaintext);
    const auxiliaryPlaintext = Array.from(
        { length: auxiliaryDegree },
        (_unused, index) => auxiliaryScores[index] ?? 0n,
    );
    const auxiliaryCiphertext = makeEncryption(
        auxiliaryDegree,
        auxiliary.modulus,
        auxiliary.scale,
        auxiliaryPlaintext,
    );
    const carries = Array.from({ length: 2 }, () =>
        Array.from({ length: 8 }, () =>
            Array.from({ length: degree }, () => 0n),
        ),
    );
    const readPlaintext = () =>
        plaintextWords.map(
            (value, index) =>
                value - 32768n + 65536n * plaintextHighBits[index],
        );
    const fheRows = () =>
        [0, 1].map((component) =>
            Array.from({ length: 9 }, (_unused, limb) =>
                Array.from(
                    { length: degree },
                    (_coefficient, position) =>
                        rowProduct(
                            (component === 0 ? fhe.publicKey : fhe.common).map(
                                (value) => digit(value, limb),
                            ),
                            fhe.ephemeral,
                            position,
                        ) -
                        digit(fhe.ciphertext[component][position], limb) +
                        (component === 0
                            ? digit(scale, limb) * readPlaintext()[position]
                            : 0n) +
                        (limb === 0
                            ? fhe.errors[component][position]
                            : carries[component][limb - 1][position]) -
                        digit(modulus, limb) *
                            fhe.quotients[component][position] -
                        (limb < 8
                            ? radix * carries[component][limb][position]
                            : 0n),
                ),
            ),
        );
    for (let component = 0; component < 2; component++)
        for (let limb = 0; limb < 8; limb++)
            fheRows()[component][limb].forEach((value, position) => {
                assert.equal(value % radix, 0n);
                carries[component][limb][position] = value / radix;
            });
    const rows = () => ({
        packing: readPlaintext().map(
            (value, position) =>
                value -
                packing.columns.reduce(
                    (sum, column, index) =>
                        sum + column[position] * (scoreWords[index] + 1n),
                    0n,
                ) -
                plaintextModulus * packingQuotient[position],
        ),
        fhe: fheRows().flat(2),
        auxiliary: [0, 1].flatMap((component) =>
            Array.from(
                { length: auxiliaryDegree },
                (_unused, position) =>
                    rowProduct(
                        component === 0
                            ? auxiliaryCiphertext.publicKey
                            : auxiliaryCiphertext.common,
                        auxiliaryCiphertext.ephemeral,
                        position,
                    ) -
                    auxiliaryCiphertext.ciphertext[component][position] +
                    auxiliaryCiphertext.errors[component][position] +
                    (component === 0 && position < scoreWords.length
                        ? auxiliary.scale * (scoreWords[position] + 1n)
                        : 0n) -
                    auxiliary.modulus *
                        auxiliaryCiphertext.quotients[component][position],
            ),
        ),
    });
    const rangeValid = () =>
        scoreWords.every((value) => value >= 0n && value <= 9n) &&
        plaintextWords.every(
            (value, index) =>
                value >= 0n &&
                value < 65536n &&
                (plaintextHighBits[index] === 0n ||
                    plaintextHighBits[index] === 1n) &&
                value * plaintextHighBits[index] === 0n,
        ) &&
        packingQuotient.every((value) => signedRange(value, 16)) &&
        [fhe, auxiliaryCiphertext].every(
            (encryption) =>
                encryption.errors
                    .flat()
                    .every((value) => signedRange(value, 7)) &&
                encryption.quotients
                    .flat()
                    .every((value) => signedRange(value, 16)) &&
                encryption.ephemeral.filter((value) => value === 1n).length ===
                    2 &&
                encryption.ephemeral.filter((value) => value === -1n).length ===
                    2 &&
                encryption.ephemeral.every(
                    (value) => value >= -1n && value <= 1n,
                ),
        ) &&
        carries.flat(2).every((value) => signedRange(value, 16));
    const decodedSlots = packing.orbit.map((exponent) => {
        const point = fieldPower(packing.root, exponent);
        const subring = Array.from({ length: degree / 2 }, (_unused, index) =>
            Number(modulo(fhe.decoded[2 * index], plaintextModulus)),
        );
        return subring.reduceRight(
            (sum, coefficient) => fieldReduce(sum * point + coefficient),
            0,
        );
    });
    return {
        scoreWords,
        plaintextWords,
        plaintextHighBits,
        fhe,
        auxiliaryCiphertext,
        rows,
        rangeValid,
        verify: () =>
            fhe.ciphertext.length === 2 &&
            auxiliaryCiphertext.ciphertext.length === 2 &&
            [fhe.common, fhe.publicKey, ...fhe.ciphertext].every(
                (coefficients) =>
                    isCanonicalCenteredPolynomial(
                        coefficients,
                        degree,
                        modulus,
                    ),
            ) &&
            [
                auxiliaryCiphertext.common,
                auxiliaryCiphertext.publicKey,
                ...auxiliaryCiphertext.ciphertext,
            ].every((coefficients) =>
                isCanonicalCenteredPolynomial(
                    coefficients,
                    auxiliaryDegree,
                    auxiliary.modulus,
                ),
            ) &&
            rangeValid() &&
            Object.values(rows())
                .flat()
                .every((value) => value % proofPrime === 0n),
        decodedSlots,
        activeSlots: packing.activeSlots,
        window: packing.window,
    };
};
