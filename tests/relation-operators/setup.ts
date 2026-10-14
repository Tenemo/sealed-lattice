import assert from 'node:assert/strict';

import { bitLength, byteLength, littleEndian } from '#tests/exact-integer.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    negate,
    power,
    powers,
    type RelationOperator,
    type Variable,
    column,
    sparse,
    createOperatorBuilder,
    createStatementReader,
    fingerprint,
    negacyclicAdjoint,
    addWeighted,
    zeros,
} from '#tests/relation-operator-model.js';
import { setupEquationWidths } from '#tests/setup-relation/equations.js';
import { deriveSetupContributionShape } from '#tests/setup-relation/shape.js';
import {
    interpolationRingDegree,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';
import {
    type Extension,
    wordFieldArithmetic,
} from '#tests/word-proof-reference/field.js';

const { zero, one, base, add, subtract, multiply, scale } = wordFieldArithmetic;

const productionSetupLayout = {
    degree: Number(fixedModulusBfvInputs.polynomialDegree),
    fheHalfSupport: Number(fixedModulusBfvInputs.secretSupportWeight / 2n),
    shareHalfSupport: Number(
        shareEncryptionParameters.encryptionSupportWeight / 2n,
    ),
};

const gadgetPolynomials = 7;

const setupHeader = (profile: SupportedProfile, degree: number) =>
    Buffer.concat([
        Buffer.from('SCO2', 'latin1'),
        littleEndian(BigInt(degree), 4),
        ...[profile.ciphertext.modulus, shareEncryptionParameters.modulus].map(
            (value) => littleEndian(value, byteLength(value)),
        ),
    ]);

// Variables in allocation order: the FHE secret, its auxiliary secret and
// each recipient's share ephemeral as positive and negative Boolean columns;
// each sharing coefficient's low and high limb parts; then each equation's
// quotient, carries and error. A signed variable takes whole 16-bit words,
// then one Boolean column per remaining bit, or one narrow word. Rows: for
// each gadget coordinate its encryption, two relinearization and
// automorphism key equations; for each recipient the constant and linear
// components of its share ciphertext; then one row per support column.
export const setupRelationOperator = (
    profile: SupportedProfile,
    statement: Uint8Array,
    alpha: Extension,
    layout = productionSetupLayout,
): RelationOperator => {
    const { degree } = layout;
    const { quotientBits, fheCarryBits, errorBits } = setupEquationWidths;
    const share = shareEncryptionParameters;
    const ciphertextModulus = profile.ciphertext.modulus;
    const fheLimbBits = 96;
    const fheLimbs = Math.ceil(bitLength(ciphertextModulus) / fheLimbBits);
    const { limbBits, carryBits, sharingCoefficientBits } =
        profile.shareLifting;
    const gadgetLength = Number(profile.gadgetLength);
    const participants = profile.participantCount;
    const shareCommon = gadgetPolynomials * gadgetLength;
    const polynomialCount = shareCommon + 3 * participants + 1;
    const header = setupHeader(profile, degree);
    if (
        statement.length !==
        header.length +
            shareCommon * degree * (1 + byteLength(ciphertextModulus)) +
            (polynomialCount - shareCommon) *
                degree *
                (1 + byteLength(share.modulus))
    )
        throw new RangeError('The setup statement has the wrong length.');
    if (!header.equals(statement.subarray(0, header.length)))
        throw new RangeError('The setup statement header differs.');
    const shape = deriveSetupContributionShape(profile);
    const columns = shape.wordColumns + shape.booleanColumns;
    const builder = createOperatorBuilder(alpha, columns);
    let nextWord = 0;
    let nextBoolean = shape.wordColumns;
    const signed = (width: number): Variable => {
        const terms: (readonly [number, bigint])[] = [];
        let remaining = width,
            shift = 0;
        while (remaining >= 16 || shift === 0) {
            const bits = Math.min(16, remaining);
            terms.push([nextWord++, 1n << BigInt(shift)]);
            remaining -= bits;
            shift += bits;
        }
        for (let bit = 0; bit < remaining; bit++)
            terms.push([nextBoolean++, 1n << BigInt(shift + bit)]);
        return { terms, offset: -(1n << BigInt(width - 1)) };
    };
    const supports: (readonly [number, number])[] = [];
    const allocateSparse = (halfSupport: number) => {
        const positive = nextBoolean;
        nextBoolean += 2;
        supports.push([positive, halfSupport], [positive + 1, halfSupport]);
        return sparse(positive);
    };
    const secret = allocateSparse(layout.fheHalfSupport);
    const auxiliary = allocateSparse(layout.fheHalfSupport);
    const ephemerals = Array.from({ length: participants }, () =>
        allocateSparse(layout.shareHalfSupport),
    );
    const sharing = Array.from(
        { length: profile.releaseThreshold - 1 },
        () => ({
            low: signed(limbBits),
            high: signed(sharingCoefficientBits - limbBits),
        }),
    );
    // Each common polynomial's convolved variables and their row weights,
    // and each value polynomial's signed row weights.
    const commonUses = new Map<
        number,
        { variable: Variable; weight: Extension }[]
    >();
    const valueUses = new Map<number, Extension[]>();
    let weight = one;
    const register = (
        commonIndex: number,
        valueIndex: number,
        convolved: Variable,
        valueSign: bigint,
    ) => {
        commonUses.set(commonIndex, [
            ...(commonUses.get(commonIndex) ?? []),
            { variable: convolved, weight },
        ]);
        valueUses.set(valueIndex, [
            ...(valueUses.get(valueIndex) ?? []),
            scale(weight, valueSign),
        ]);
    };
    const limbWeight = power(alpha, degree);
    const fheModulus = fingerprint(ciphertextModulus, fheLimbBits, limbWeight);
    // common*convolved + direct + value - Q*q - error = 0 in FHE limbs.
    const key = (
        commonIndex: number,
        valueIndex: number,
        convolved: Variable,
        direct?: Readonly<{
            variable: Variable;
            factor: Extension;
            automorphism: number;
        }>,
    ) => {
        const quotient = signed(quotientBits);
        const carries = Array.from({ length: fheLimbs - 1 }, () =>
            signed(fheCarryBits),
        );
        const error = signed(errorBits);
        register(commonIndex, valueIndex, convolved, 1n);
        if (direct !== undefined)
            builder.putGeometric(
                direct.variable,
                degree,
                multiply(weight, direct.factor),
                direct.automorphism,
            );
        builder.putGeometric(
            quotient,
            degree,
            negate(multiply(weight, fheModulus)),
        );
        builder.putGeometric(error, degree, negate(weight));
        let factor = subtract(limbWeight, base(1n << BigInt(fheLimbBits)));
        for (const carry of carries) {
            builder.putGeometric(carry, degree, multiply(weight, factor));
            factor = multiply(factor, limbWeight);
        }
        weight = multiply(weight, power(limbWeight, fheLimbs));
    };
    for (let gadget = 0; gadget < gadgetLength; gadget++) {
        const gadgetDigit = fingerprint(
            fixedModulusBfvInputs.gadgetBase ** BigInt(gadget),
            fheLimbBits,
            limbWeight,
        );
        const first = gadgetPolynomials * gadget;
        key(first, first + 1, secret);
        key(first, first + 2, auxiliary, {
            variable: secret,
            factor: negate(gadgetDigit),
            automorphism: 1,
        });
        key(first + 3, first + 4, secret, {
            variable: auxiliary,
            factor: gadgetDigit,
            automorphism: 1,
        });
        key(first + 5, first + 6, secret, {
            variable: secret,
            factor: negate(gadgetDigit),
            automorphism: 5,
        });
    }
    // key*ephemeral + scale*(secret + sum_k sharing_k*Z^(a*(k+1))) +
    // error - Q_s*q = constant, and common*ephemeral + error - Q_s*q =
    // linear, in two share limbs. Each sharing coefficient is low +
    // radix*high + radix/2, so the target takes the halves' images.
    const shareRadix = 1n << BigInt(limbBits);
    const shareModulus = fingerprint(share.modulus, limbBits, limbWeight);
    const pointStride = degree / interpolationRingDegree(participants);
    assert.ok(Number.isInteger(pointStride));
    const rowPowers = powers(alpha, degree);
    const encryptedShare = (
        commonIndex: number,
        valueIndex: number,
        ephemeral: Variable,
        point?: number,
    ) => {
        const quotient = signed(quotientBits);
        const carry = signed(point === undefined ? fheCarryBits : carryBits);
        const error = signed(errorBits);
        register(commonIndex, valueIndex, ephemeral, -1n);
        if (point !== undefined) {
            const messageWeight = scale(weight, share.scale);
            builder.putGeometric(secret, degree, messageWeight);
            const units = Array.from({ length: degree }, () => 0n);
            sharing.forEach(({ low, high }, coefficient) => {
                const shift = (point * (coefficient + 1)) % (2 * degree);
                builder.putGeometric(low, degree, messageWeight, 1, shift);
                builder.putGeometric(
                    high,
                    degree,
                    multiply(messageWeight, limbWeight),
                    1,
                    shift,
                );
                for (let input = 0; input < degree; input++) {
                    const exponent = (input + shift) % (2 * degree);
                    units[exponent % degree] += exponent < degree ? 1n : -1n;
                }
            });
            const unit = share.scale * (shareRadix / 2n);
            const offsets = new Map<bigint, Extension>();
            let offsetSum = zero;
            units.forEach((count, position) => {
                let offset = offsets.get(count);
                if (offset === undefined) {
                    offset = fingerprint(count * unit, limbBits, limbWeight);
                    offsets.set(count, offset);
                }
                offsetSum = add(
                    offsetSum,
                    multiply(rowPowers[position], offset),
                );
            });
            builder.addTarget(negate(multiply(weight, offsetSum)));
        }
        builder.putGeometric(
            quotient,
            degree,
            negate(multiply(weight, shareModulus)),
        );
        builder.putGeometric(
            carry,
            degree,
            multiply(weight, subtract(limbWeight, base(shareRadix))),
        );
        builder.putGeometric(error, degree, weight);
        weight = multiply(weight, multiply(limbWeight, limbWeight));
    };
    ephemerals.forEach((ephemeral, recipient) => {
        const recipientKey = shareCommon + 1 + 3 * recipient;
        encryptedShare(
            recipientKey,
            recipientKey + 1,
            ephemeral,
            recipient * pointStride,
        );
        encryptedShare(shareCommon, recipientKey + 2, ephemeral);
    });
    for (const [supportColumn, half] of supports) {
        builder.putOnes(column(supportColumn), degree, weight);
        builder.addTarget(scale(weight, BigInt(half)));
        weight = multiply(weight, alpha);
    }
    assert.equal(nextWord, shape.wordColumns);
    assert.equal(nextBoolean, columns);
    // Each polynomial is common, entering its convolved variables'
    // adjoints, or a value, entering the target.
    const adjoints = new Map<Variable, Extension[]>();
    const reader = createStatementReader(statement, header.length, alpha);
    for (let index = 0; index < polynomialCount; index++) {
        const fhe = index < shareCommon;
        const polynomial = reader.next(
            degree,
            fhe ? ciphertextModulus : share.modulus,
            fhe ? fheLimbBits : limbBits,
        );
        const uses = commonUses.get(index);
        const values = valueUses.get(index);
        assert.ok((uses === undefined) !== (values === undefined), `${index}`);
        if (uses !== undefined) {
            const adjoint = negacyclicAdjoint(polynomial, alpha);
            for (const use of uses) {
                let accumulator = adjoints.get(use.variable);
                if (accumulator === undefined) {
                    accumulator = zeros(degree);
                    adjoints.set(use.variable, accumulator);
                }
                addWeighted(accumulator, use.weight, adjoint);
            }
        } else
            for (const value of values!)
                builder.addTarget(negate(multiply(value, polynomial.total)));
    }
    reader.finish();
    for (const [variable, values] of adjoints)
        builder.put(
            variable,
            `adjoint:${variable.terms[0][0]}`,
            { kind: 'values', values },
            one,
        );
    return builder.finish(weight);
};
