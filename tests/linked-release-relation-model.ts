import assert from 'node:assert/strict';

import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

const sharing = compileWideShareLiftingCensus();
const release = compileFixedModulusBfvCensus();
const radix = sharing.radix;
const releaseRadix = 1n << 48n;
const degree = 16;
const modulo = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;
const center = (value: bigint, modulus: bigint) => {
    const result = modulo(value, modulus);
    return result > modulus / 2n ? result - modulus : result;
};
const magnitude = (value: bigint) => (value < 0n ? -value : value);
const signedDigit = (value: bigint, limb: number, base: bigint) =>
    (value < 0n ? -1n : 1n) *
    ((magnitude(value) / base ** BigInt(limb)) % base);
const inRange = (value: bigint, bits: number) =>
    value >= -(1n << BigInt(bits - 1)) && value < 1n << BigInt(bits - 1);
const privateDigit = (
    value: bigint,
    bits: number,
    limb: number,
    limbBits: number,
) => {
    const base = 1n << BigInt(limbBits);
    const count = Math.ceil(bits / limbBits);
    if (limb >= count) return 0n;
    let digit =
        (modulo(value, 1n << BigInt(bits)) / base ** BigInt(limb)) % base;
    if (limb === count - 1 && value < 0n)
        digit -= 1n << BigInt(bits - limbBits * (count - 1));
    return digit;
};
const convolution = (left: readonly bigint[], right: readonly bigint[]) => {
    const ordinary = Array.from({ length: 2 * degree - 1 }, () => 0n);
    for (let first = 0; first < degree; first++)
        for (let second = 0; second < degree; second++)
            ordinary[first + second] += left[first] * right[second];
    return left.map(
        (_value, position) =>
            ordinary[position] - (ordinary[position + degree] ?? 0n),
    );
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
                right[(row - index + degree) % degree] *
                (row < index ? -1n : 1n),
        0n,
    );

export const compileLinkedReleaseRelationCensus = () => {
    const recipientSupport = sharing.encryptionSupportWeight;
    const shareBits = 120;
    const decodingErrorBits = 24;
    const decodingQuotientBits = 16;
    const decodingCarryBits = 30;
    const decodingErrorRadius = 1n << BigInt(decodingErrorBits - 1);
    const decodingCarryRadius = 1n << BigInt(decodingCarryBits - 1);
    const quotientRadius = 1n << BigInt(decodingQuotientBits - 1);
    const trueDecodingQuotientBound =
        ((recipientSupport + 1n) * (sharing.modulus / 2n) +
            sharing.scale * (1n << BigInt(shareBits - 1)) +
            decodingErrorRadius) /
        sharing.modulus;
    const trueDecodingCarryBound =
        ((recipientSupport + trueDecodingQuotientBound + 2n) * (radix - 1n) +
            sharing.scale * (radix / 2n) +
            decodingErrorRadius) /
            radix +
        1n;
    const decodingResidualBound =
        (recipientSupport + quotientRadius + 2n) * (radix - 1n) +
        sharing.scale * (radix / 2n) +
        decodingErrorRadius +
        decodingCarryRadius * (radix + 1n);
    assert.ok(2n * decodingErrorRadius < sharing.scale);
    assert.ok(
        2n *
            (sharing.scale * (1n << BigInt(shareBits - 1)) +
                decodingErrorRadius) <
            sharing.modulus,
    );
    assert.ok(sharing.aggregateSharingMaximum < 1n << BigInt(shareBits - 1));
    assert.ok(trueDecodingQuotientBound < quotientRadius);
    assert.ok(trueDecodingCarryBound < decodingCarryRadius);
    assert.ok(decodingResidualBound < sharing.proofPrime);
    const signedWidths = [
        16,
        16,
        7,
        shareBits,
        decodingErrorBits,
        decodingQuotientBits,
        decodingCarryBits,
        release.releaseNoiseBits,
        144,
        ...Array.from({ length: 5 }, () => 72),
    ];
    const wordColumns = signedWidths.reduce(
        (sum, bits) => sum + Math.ceil(bits / 16),
        0,
    );
    const narrowMemberships = signedWidths.filter(
        (bits) => bits % 16 !== 0,
    ).length;
    return {
        shareBits,
        decodingErrorBits,
        decodingQuotientBits,
        decodingCarryBits,
        trueDecodingQuotientBound,
        trueDecodingCarryBound,
        decodingResidualBound,
        releaseResidualBound: compileReleaseShareLiftingCensus().residualBound,
        wordColumns,
        narrowMemberships,
        lookupEntries: wordColumns + narrowMemberships,
        booleanColumns: 2,
        affineRows: 10n * release.polynomialDegree + 2n,
    };
};

// This fixture retains the full moduli and accepted integer widths. Only the
// physical ring and honest sparse supports are reduced for independent algebra.
export const createLinkedReleaseRelationModel = (seed = 1n) => {
    const bounds = compileLinkedReleaseRelationCensus();
    const zero = () => Array.from({ length: degree }, () => 0n);
    let state = seed;
    const random = () =>
        (state =
            (state * 6364136223846793005n + 1442695040888963407n) &
            ((1n << 256n) - 1n));
    const sparse = () => {
        const result = zero();
        let filled = 0;
        while (filled < 4) {
            const position = Number(random() % BigInt(degree));
            if (result[position] !== 0n) continue;
            result[position] = filled++ < 2 ? 1n : -1n;
        }
        return result;
    };
    const recipientSecret = zero().map((_value, index) =>
        index < 4 ? (index < 2 ? 1n : -1n) : 0n,
    );
    const errors = () =>
        zero().map((_value, index) =>
            seed === 0n
                ? index % 2 === 0
                    ? -64n
                    : 63n
                : (random() & 127n) - 64n,
        );
    const common = zero().map(() => center(random(), sharing.modulus));
    const keyError = errors();
    const keyProduct = convolution(common, recipientSecret);
    const publicKey = keyProduct.map((value, index) =>
        center(-value + keyError[index], sharing.modulus),
    );
    const keyQuotient = keyProduct.map(
        (value, index) =>
            (value + publicKey[index] - keyError[index]) / sharing.modulus,
    );
    const encryptedConstant = zero(),
        encryptedLinear = zero(),
        share = zero();
    for (
        let contributor = 0;
        contributor < Number(release.participantCount);
        contributor++
    ) {
        const message = zero().map((_value, index) =>
            seed === 0n
                ? index % 2 === 0
                    ? -3n * sharing.sharingRadius
                    : 3n * (sharing.sharingRadius - 1n)
                : center(random(), 6n * sharing.sharingRadius),
        );
        const ephemeral = sparse(),
            errorConstant = errors(),
            errorLinear = errors();
        const firstProduct = convolution(publicKey, ephemeral),
            secondProduct = convolution(common, ephemeral);
        for (let index = 0; index < degree; index++) {
            share[index] += message[index];
            encryptedConstant[index] = center(
                encryptedConstant[index] +
                    firstProduct[index] +
                    sharing.scale * message[index] +
                    errorConstant[index],
                sharing.modulus,
            );
            encryptedLinear[index] = center(
                encryptedLinear[index] +
                    secondProduct[index] +
                    errorLinear[index],
                sharing.modulus,
            );
        }
    }
    const phaseProduct = convolution(encryptedLinear, recipientSecret);
    const decodedPhase = encryptedConstant.map((value, index) =>
        center(value + phaseProduct[index], sharing.modulus),
    );
    const decodingError = decodedPhase.map(
        (value, index) => value - sharing.scale * share[index],
    );
    const decodingQuotient = encryptedConstant.map(
        (value, index) =>
            (value +
                phaseProduct[index] -
                sharing.scale * share[index] -
                decodingError[index]) /
            sharing.modulus,
    );
    const targetLinear = zero().map(() =>
        center(random(), release.releaseModulus),
    );
    const noise = zero().map((_value, index) =>
        seed === 0n
            ? index % 2 === 0
                ? -(1n << BigInt(release.releaseNoiseBits - 1))
                : (1n << BigInt(release.releaseNoiseBits - 1)) - 1n
            : (random() % (1n << BigInt(release.releaseNoiseBits))) -
              (1n << BigInt(release.releaseNoiseBits - 1)),
    );
    const partial = zero(),
        releaseQuotient = zero();
    const keyCarry = zero(),
        decodingCarry = zero(),
        releaseCarries = Array.from({ length: 5 }, zero);
    const lowerShare = () =>
        share.map((value) => modulo(value, radix) - radix / 2n);
    const upperShare = () =>
        share.map(
            (value) =>
                (value - (modulo(value, radix) - radix / 2n) - radix / 2n) /
                radix,
        );
    const keyRows = () =>
        [0, 1].map((limb) =>
            zero().map(
                (_value, position) =>
                    rowProduct(
                        common.map((value) => signedDigit(value, limb, radix)),
                        recipientSecret,
                        position,
                    ) +
                    signedDigit(publicKey[position], limb, radix) -
                    signedDigit(sharing.modulus, limb, radix) *
                        keyQuotient[position] +
                    (limb === 0
                        ? -keyError[position] - radix * keyCarry[position]
                        : keyCarry[position]),
            ),
        );
    const decodingRows = () =>
        [0, 1].map((limb) =>
            zero().map(
                (_value, position) =>
                    rowProduct(
                        encryptedLinear.map((value) =>
                            signedDigit(value, limb, radix),
                        ),
                        recipientSecret,
                        position,
                    ) +
                    signedDigit(encryptedConstant[position], limb, radix) -
                    sharing.scale *
                        (limb === 0 ? lowerShare() : upperShare())[position] -
                    signedDigit(sharing.scale * (radix / 2n), limb, radix) -
                    signedDigit(sharing.modulus, limb, radix) *
                        decodingQuotient[position] +
                    (limb === 0
                        ? -decodingError[position] -
                          radix * decodingCarry[position]
                        : decodingCarry[position]),
            ),
        );
    const releaseRows = () =>
        Array.from({ length: 6 }, (_unused, limb) =>
            zero().map((_value, position) => {
                let residual =
                    (limb > 0 ? releaseCarries[limb - 1][position] : 0n) -
                    (limb < 5
                        ? releaseRadix * releaseCarries[limb][position]
                        : 0n) -
                    signedDigit(partial[position], limb, releaseRadix) +
                    4n *
                        privateDigit(
                            noise[position],
                            release.releaseNoiseBits,
                            limb,
                            48,
                        );
                for (let publicLimb = 0; publicLimb < 4; publicLimb++) {
                    const privateLimb = limb - publicLimb;
                    if (privateLimb < 0 || privateLimb >= 3) continue;
                    residual +=
                        4n *
                            rowProduct(
                                targetLinear.map((value) =>
                                    signedDigit(
                                        value,
                                        publicLimb,
                                        releaseRadix,
                                    ),
                                ),
                                share.map((value) =>
                                    privateDigit(
                                        value,
                                        bounds.shareBits,
                                        privateLimb,
                                        48,
                                    ),
                                ),
                                position,
                            ) -
                        signedDigit(
                            release.releaseModulus,
                            publicLimb,
                            releaseRadix,
                        ) *
                            privateDigit(
                                releaseQuotient[position],
                                144,
                                privateLimb,
                                48,
                            );
                }
                return residual;
            }),
        );
    const recoverCarry = (
        residuals: readonly bigint[],
        destination: bigint[],
        base: bigint,
    ) =>
        residuals.forEach((value, position) => {
            assert.equal(value % base, 0n);
            destination[position] = value / base;
        });
    recoverCarry(keyRows()[0], keyCarry, radix);
    recoverCarry(decodingRows()[0], decodingCarry, radix);
    const derivePartial = () => {
        const product = convolution(targetLinear, share);
        for (let position = 0; position < degree; position++) {
            const raw = 4n * (product[position] + noise[position]);
            partial[position] = center(raw, release.releaseModulus);
            releaseQuotient[position] =
                (raw - partial[position]) / release.releaseModulus;
        }
        releaseCarries.forEach((carry) => carry.fill(0n));
        for (let limb = 0; limb < 5; limb++)
            recoverCarry(
                releaseRows()[limb],
                releaseCarries[limb],
                releaseRadix,
            );
    };
    derivePartial();
    const boundedVariables: readonly (readonly [readonly bigint[], number])[] =
        [
            [keyError, 7],
            [keyQuotient, 16],
            [keyCarry, 16],
            [share, bounds.shareBits],
            [decodingError, bounds.decodingErrorBits],
            [decodingQuotient, bounds.decodingQuotientBits],
            [decodingCarry, bounds.decodingCarryBits],
            [noise, release.releaseNoiseBits],
            [releaseQuotient, 144],
            ...releaseCarries.map((values) => [values, 72] as const),
        ];
    const rangeValid = () =>
        boundedVariables.every(([values, bits]) =>
            values.every((value) => inRange(value, bits)),
        );
    const rows = () => ({
        key: keyRows().flat(),
        decoding: decodingRows().flat(),
        partial: releaseRows().flat(),
    });
    const verify = () =>
        rangeValid() &&
        recipientSecret.every((value) => value >= -1n && value <= 1n) &&
        recipientSecret.filter((value) => value === 1n).length === 2 &&
        recipientSecret.filter((value) => value === -1n).length === 2 &&
        Object.values(rows())
            .flat()
            .every((value) => modulo(value, sharing.proofPrime) === 0n);
    return {
        recipientSecret,
        common,
        publicKey,
        encryptedConstant,
        encryptedLinear,
        share,
        decodingError,
        targetLinear,
        noise,
        partial,
        rows,
        rangeValid,
        verify,
        derivePartial,
        decodingCarry,
        decodedPhase,
    };
};
