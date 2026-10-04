// Exact arithmetic and resource experiment for public opening shares.
// It creates no verified package, broadcast decision or decryption authority.
// Original-key custody, authenticated context and the new proof-role security
// remain obligations of the protocol that would consume this relation.
import { compileWordProverResources } from '#tests/browser-word-prover-resource-model.js';
import { compileWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    deriveSupportedShareLifting,
    interpolationRingDegree,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

type Polynomial = readonly bigint[];
const absolute = (value: bigint) => (value < 0n ? -value : value);
const bits = (value: bigint) => (value === 0n ? 0 : value.toString(2).length);
const ceilDivide = (value: bigint, divisor: bigint) =>
    (value + divisor - 1n) / divisor;
const residue = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;
const centered = (value: bigint, modulus: bigint) => {
    const positive = residue(value, modulus);
    return positive > modulus / 2n ? positive - modulus : positive;
};

export const openingShareParameters = (participantCount: number) => {
    const registration = compileRegistrationKeyRelationCensus();
    const sharing = deriveSupportedShareLifting(participantCount);
    const field = compileSmallLimbProofFieldCensus();
    const { modulus, scale, encryptionSupportWeight, errorBound } =
        shareEncryptionParameters;
    if (modulus !== registration.modulus)
        throw new Error('The registered recipient encryption modulus changed.');
    const maximumShare =
        1n + BigInt(sharing.sharingDegree) * sharing.sharingRadius;
    const honestError =
        encryptionSupportWeight * registration.error +
        errorBound * (registration.support + 1n);
    const recoveryErrorBits = bits(honestError) + 1;
    const recoveryErrorRadius = 1n << BigInt(recoveryErrorBits - 1);
    // The registration relation uses one signed word for quotient and carry.
    const signedWordBits = 16;
    const signedWordRadius = 1n << BigInt(signedWordBits - 1);
    const honestQuotient =
        ((registration.support + 1n) * (modulus / 2n) + honestError) / modulus;
    const honestCarry = ceilDivide(
        (registration.support + 1n + honestQuotient) *
            (registration.radix - 1n) +
            honestError,
        registration.radix,
    );
    const maximumLimbResidual =
        (registration.support + 1n + signedWordRadius) *
            (registration.radix - 1n) +
        recoveryErrorRadius +
        signedWordRadius * (registration.radix + 1n);
    if (
        2n * maximumShare >= field.modulus ||
        2n * (scale * maximumShare + honestError) >= modulus ||
        honestError + recoveryErrorRadius >= scale ||
        honestQuotient >= signedWordRadius ||
        honestCarry >= signedWordRadius ||
        maximumLimbResidual >= field.modulus
    )
        throw new Error('The public opening-share lifting bounds fail.');
    return {
        participantCount,
        selectedCount: sharing.sharingDegree + 1,
        sharingDegree: sharing.sharingDegree,
        sharingRadius: sharing.sharingRadius,
        maximumShare,
        modulus,
        scale,
        proofPrime: field.modulus,
        radix: registration.radix,
        recipientSupport: registration.support,
        ephemeralSupport: encryptionSupportWeight,
        keyErrorRadius: registration.error,
        encryptionErrorRadius: errorBound,
        honestError,
        recoveryErrorBits,
        recoveryErrorRadius,
        signedWordBits,
        signedWordRadius,
        honestQuotient,
        honestCarry,
        maximumLimbResidual,
        shareCoefficientBytes: 1 + Math.ceil(bits(maximumShare) / 8),
    };
};
type Parameters = ReturnType<typeof openingShareParameters>;

export const compileOpeningShareResources = (
    participantCount: number,
    physicalDegree: bigint,
) => {
    const parameters = openingShareParameters(participantCount);
    const registration = compileRegistrationKeyRelationCensus();
    if (
        physicalDegree < parameters.recipientSupport ||
        physicalDegree > registration.degree ||
        (physicalDegree & (physicalDegree - 1n)) !== 0n
    )
        throw new RangeError('Invalid opening-share physical degree.');
    const widths = [
        16,
        16,
        7,
        ...Array.from({ length: parameters.selectedCount }, () => [
            16,
            16,
            parameters.recoveryErrorBits,
        ]).flat(),
    ];
    const wordColumns = widths.reduce(
        (sum, width) => sum + Math.max(1, Math.floor(width / 16)),
        0,
    );
    const booleanColumns =
        2 +
        widths.reduce((sum, width) => sum + (width < 16 ? 0 : width % 16), 0);
    const narrowWordColumns = widths.filter((width) => width < 16).length;
    const lookupEntries = wordColumns + narrowWordColumns;
    const columns = wordColumns + booleanColumns;
    const publicShareBytes =
        BigInt(parameters.selectedCount * parameters.shareCoefficientBytes) *
        physicalDegree;
    const sourcePolynomialBytes =
        (2n + 2n * BigInt(parameters.selectedCount)) *
        physicalDegree *
        BigInt(1 + Math.ceil(bits(parameters.modulus) / 8));
    return {
        parameters,
        physicalDegree,
        widths,
        wordColumns,
        booleanColumns,
        narrowWordColumns,
        lookupEntries,
        disjointPairs: 1,
        supportRows: 2,
        affineRows:
            2n * BigInt(parameters.selectedCount + 1) * physicalDegree + 2n,
        publicShareBytes,
        // Original A/P and each source U/V are predecessors, not new uploads.
        // Scope framing, signatures, storage and full workflow costs are absent.
        expandedStatementPolynomialBytes:
            sourcePolynomialBytes + publicShareBytes,
        layout: compileWordProofLayout(columns, lookupEntries),
        proofEngine: compileWordProverResources({
            columns,
            lookups: lookupEntries,
            preparedAdjointBytes: 0n,
        }),
    };
};

export const openingProduct = (
    left: Polynomial,
    right: Polynomial,
): bigint[] => {
    if (left.length !== right.length)
        throw new RangeError('Polynomial lengths differ.');
    const output = Array<bigint>(left.length).fill(0n);
    for (let rightPosition = 0; rightPosition < right.length; rightPosition++) {
        if (right[rightPosition] === 0n) continue;
        for (let leftPosition = 0; leftPosition < left.length; leftPosition++) {
            const index = leftPosition + rightPosition;
            output[index % left.length] +=
                (index < left.length ? 1n : -1n) *
                left[leftPosition] *
                right[rightPosition];
        }
    }
    return output;
};
const shifted = (values: Polynomial, exponent: number): bigint[] => {
    const output = Array<bigint>(values.length).fill(0n);
    for (let index = 0; index < values.length; index++) {
        const destination = index + exponent;
        output[destination % values.length] +=
            (Math.floor(destination / values.length) % 2 === 0 ? 1n : -1n) *
            values[index];
    }
    return output;
};
const sparse = (degree: number, support: bigint, shift: number): bigint[] =>
    Array.from({ length: degree }, (_unused, position) => {
        const selected = BigInt((13 * position + shift) % degree);
        return selected < support / 2n ? 1n : selected < support ? -1n : 0n;
    });

export const createOpeningShareExample = (
    participantCount: number,
    recipient: number,
    seedBit: 0 | 1,
    sequence: number,
) => {
    const parameters = openingShareParameters(participantCount);
    if (
        !Number.isSafeInteger(recipient) ||
        recipient < 0 ||
        recipient >= participantCount
    )
        throw new RangeError('Unknown recipient.');
    // A reduced ring with actual support weights, including zero positions.
    // Its lattice hardness and proof system are not tested by this model.
    const degree = 2 * Number(parameters.recipientSupport);
    const common = Array.from({ length: degree }, (_unused, position) =>
        centered(
            (parameters.modulus / 257n) *
                BigInt(53 * position + 19 + 7 * sequence) +
                BigInt(position * position),
            parameters.modulus,
        ),
    );
    const secret = sparse(
        degree,
        parameters.recipientSupport,
        17 * recipient + sequence,
    );
    const keyErrors = Array.from({ length: degree }, (_unused, position) =>
        (position + sequence) % 2 === 0
            ? -parameters.keyErrorRadius
            : parameters.keyErrorRadius - 1n,
    );
    const keyProducts = openingProduct(common, secret);
    const publicKey = keyProducts.map((value, index) =>
        centered(-value + keyErrors[index], parameters.modulus),
    );
    const point =
        (recipient * degree) / interpolationRingDegree(participantCount);
    const packages = Array.from(
        { length: parameters.selectedCount },
        (_unused, packageIndex) => {
            const seed = Array.from({ length: degree }, (_value, index) =>
                index < 4 ? BigInt(seedBit) : 0n,
            );
            const coefficients = Array.from(
                { length: parameters.sharingDegree },
                (_value, coefficient) =>
                    Array.from({ length: degree }, (_coefficient, position) => {
                        const edge =
                            (position + coefficient + packageIndex + sequence) %
                            4;
                        return [
                            -parameters.sharingRadius,
                            -parameters.sharingRadius + 1n,
                            parameters.sharingRadius - 2n,
                            parameters.sharingRadius - 1n,
                        ][edge];
                    }),
            );
            const message = [...seed];
            for (const [coefficient, values] of coefficients.entries()) {
                const rotated = shifted(values, point * (coefficient + 1));
                for (let index = 0; index < degree; index++)
                    message[index] += rotated[index];
            }
            // Neither seedBit nor the message drives the private encryption tape.
            const ephemeral = sparse(
                degree,
                parameters.ephemeralSupport,
                29 * packageIndex + sequence,
            );
            const errors = [0, 1].map((component) =>
                Array.from({ length: degree }, (_value, position) =>
                    (position + component + packageIndex + sequence) % 2 === 0
                        ? -parameters.encryptionErrorRadius
                        : parameters.encryptionErrorRadius - 1n,
                ),
            );
            const constant = openingProduct(publicKey, ephemeral).map(
                (value, index) =>
                    centered(
                        value +
                            parameters.scale * message[index] +
                            errors[0][index],
                        parameters.modulus,
                    ),
            );
            const linear = openingProduct(common, ephemeral).map(
                (value, index) =>
                    centered(value + errors[1][index], parameters.modulus),
            );
            return {
                seed,
                coefficients,
                message,
                ephemeral,
                errors,
                constant,
                linear,
            };
        },
    );
    return {
        parameters,
        degree,
        recipient,
        common,
        publicKey,
        secret,
        keyErrors,
        packages,
    };
};
export type OpeningShareExample = ReturnType<typeof createOpeningShareExample>;

const requireShare = (
    parameters: Parameters,
    values: Polynomial,
    degree: number,
) => {
    if (
        values.length !== degree ||
        values.some((value) => absolute(value) > parameters.maximumShare)
    )
        throw new RangeError('Public share outside its canonical range.');
};
export const encodeOpeningShare = (
    participantCount: number,
    values: Polynomial,
    degree: number,
): Uint8Array => {
    const parameters = openingShareParameters(participantCount);
    requireShare(parameters, values, degree);
    const width = parameters.shareCoefficientBytes;
    const encoded = new Uint8Array(degree * width);
    for (const [index, value] of values.entries()) {
        encoded[index * width] = value < 0n ? 1 : 0;
        let magnitude = absolute(value);
        for (let byte = 1; byte < width; byte++) {
            encoded[index * width + byte] = Number(magnitude & 255n);
            magnitude >>= 8n;
        }
    }
    return encoded;
};
export const decodeOpeningShare = (
    participantCount: number,
    encoded: Uint8Array,
    degree: number,
): bigint[] => {
    const parameters = openingShareParameters(participantCount);
    const width = parameters.shareCoefficientBytes;
    if (encoded.length !== degree * width)
        throw new RangeError('Public share byte length.');
    const values: bigint[] = [];
    for (let index = 0; index < degree; index++) {
        const sign = encoded[index * width];
        let magnitude = 0n;
        for (let byte = width - 1; byte > 0; byte--)
            magnitude =
                256n * magnitude + BigInt(encoded[index * width + byte]);
        if (sign > 1 || (sign === 1 && magnitude === 0n))
            throw new RangeError('Noncanonical public share.');
        values.push(sign === 1 ? -magnitude : magnitude);
    }
    requireShare(parameters, values, degree);
    return values;
};

export const openingDifference = (
    constant: Polynomial,
    message: Polynomial,
    parameters: Parameters,
): bigint[] => {
    if (constant.length !== message.length)
        throw new RangeError('Share and ciphertext lengths differ.');
    return constant.map((value, index) =>
        centered(value - parameters.scale * message[index], parameters.modulus),
    );
};

export const deriveOpeningShareWitness = (
    example: OpeningShareExample,
    messages: readonly Polynomial[],
    secret: Polynomial = example.secret,
) => {
    const { parameters, degree } = example;
    if (
        secret.length !== degree ||
        secret.some((value) => value < -1n || value > 1n) ||
        [-1n, 1n].some(
            (sign) =>
                BigInt(secret.filter((value) => value === sign).length) !==
                parameters.recipientSupport / 2n,
        ) ||
        messages.length !== parameters.selectedCount
    )
        throw new RangeError('Opening witness shape or sparse support.');
    for (const message of messages) requireShare(parameters, message, degree);
    const equations = [
        {
            constant: example.publicKey,
            linear: example.common,
            errorRadius: parameters.keyErrorRadius,
        },
        ...example.packages.map((source, index) => ({
            constant: openingDifference(
                source.constant,
                messages[index],
                parameters,
            ),
            linear: source.linear,
            errorRadius: parameters.recoveryErrorRadius,
        })),
    ];
    const digit = (value: bigint, index: number) =>
        (value < 0n ? -1n : 1n) *
        ((absolute(value) / parameters.radix ** BigInt(index)) %
            parameters.radix);
    return equations.map((equation) => {
        const products = openingProduct(equation.linear, secret);
        const raw = products.map(
            (value, index) => value + equation.constant[index],
        );
        const errors = raw.map((value) => centered(value, parameters.modulus));
        if (
            errors.some(
                (value) =>
                    value < -equation.errorRadius ||
                    value >= equation.errorRadius,
            )
        )
            throw new RangeError('Opening relation noise.');
        const quotients = raw.map(
            (value, index) => (value - errors[index]) / parameters.modulus,
        );
        const lowerProducts = openingProduct(
            equation.linear.map((value) => digit(value, 0)),
            secret,
        );
        const lower = lowerProducts.map(
            (value, index) =>
                value +
                digit(equation.constant[index], 0) -
                errors[index] -
                digit(parameters.modulus, 0) * quotients[index],
        );
        if (lower.some((value) => value % parameters.radix !== 0n))
            throw new Error('Nonintegral opening carry.');
        const carries = lower.map((value) => value / parameters.radix);
        if (
            [...quotients, ...carries].some(
                (value) =>
                    value < -parameters.signedWordRadius ||
                    value >= parameters.signedWordRadius,
            )
        )
            throw new RangeError('Opening quotient or carry range.');
        const upperProducts = openingProduct(
            equation.linear.map((value) => digit(value, 1)),
            secret,
        );
        const upperResiduals = upperProducts.map(
            (value, index) =>
                value +
                digit(equation.constant[index], 1) -
                digit(parameters.modulus, 1) * quotients[index] +
                carries[index],
        );
        if (upperResiduals.some((value) => value !== 0n))
            throw new Error('Opening integer equation.');
        return { errors, quotients, carries };
    });
};

// A true outer package and ANY bounded recipient key satisfying its original
// registration equation give noise bounded by honestError. A distinct claimed
// share would require this modular distance to fit both noise intervals.
export const openingShareSeparation = (
    parameters: Parameters,
    difference: bigint,
) => {
    const displacement = residue(
        parameters.scale * difference,
        parameters.modulus,
    );
    return {
        distance:
            displacement < parameters.modulus - displacement
                ? displacement
                : parameters.modulus - displacement,
        maximumNoiseDifference:
            parameters.honestError + parameters.recoveryErrorRadius,
    };
};
