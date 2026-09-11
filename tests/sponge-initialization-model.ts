import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

export const boundedResidueFiberWord = (
    modulus: bigint,
    wordBits: bigint,
    residue: bigint,
    randomWord: bigint,
    randomBits: bigint,
) => {
    if (
        wordBits < 1n ||
        wordBits > 4096n ||
        randomBits < 1n ||
        randomBits > 8192n
    )
        throw new RangeError('Invalid finite sampling width.');
    const space = 1n << wordBits;
    if (
        modulus < 2n ||
        modulus > space ||
        residue < 0n ||
        residue >= modulus ||
        randomWord < 0n ||
        randomWord >= 1n << randomBits
    )
        throw new RangeError('Invalid residue-fiber input.');
    const count = (space - 1n - residue) / modulus + 1n;
    return residue + modulus * (randomWord % count);
};

export const forcePermutationMappings = (
    permutation: readonly number[],
    mappings: readonly (readonly [number, number])[],
) => {
    const size = permutation.length;
    if (
        size < 1 ||
        size > 16 ||
        new Set(permutation).size !== size ||
        permutation.some(
            (value) => !Number.isInteger(value) || value < 0 || value >= size,
        ) ||
        new Set(mappings.map(([input]) => input)).size !== mappings.length ||
        new Set(mappings.map(([, output]) => output)).size !==
            mappings.length ||
        mappings.some((pair) =>
            pair.some(
                (value) =>
                    !Number.isInteger(value) || value < 0 || value >= size,
            ),
        )
    )
        throw new RangeError('Invalid bounded permutation constraints.');
    const current = [...permutation];
    for (const [input, output] of mappings) {
        const otherInput = current.indexOf(output);
        [current[input], current[otherInput]] = [
            current[otherInput],
            current[input],
        ];
    }
    return current;
};

export const squeezingCapacityCondition = (
    permutation: readonly number[],
    rateSize: number,
    chains: readonly Readonly<{ start: number; length: number }>[],
) => {
    if (
        !Number.isInteger(rateSize) ||
        rateSize < 2 ||
        permutation.length % rateSize !== 0 ||
        chains.some(
            ({ start, length }) =>
                !Number.isInteger(start) ||
                start < 0 ||
                start >= rateSize ||
                !Number.isInteger(length) ||
                length < 1,
        ) ||
        new Set(chains.map(({ start }) => start)).size !== chains.length
    )
        throw new RangeError('Invalid fixed squeezing chains.');
    forcePermutationMappings(permutation, []);
    const capacities = new Set<number>(),
        rates: number[] = [];
    for (const chain of chains) {
        let input = chain.start;
        for (let step = 0; step < chain.length; step++) {
            const output = permutation[input];
            const capacity = Math.floor(output / rateSize);
            if (capacity === 0 || capacities.has(capacity)) return undefined;
            capacities.add(capacity);
            rates.push(output % rateSize);
            input = output;
        }
    }
    return rates;
};

export const staticSpongeConditioningBound = (
    rateBits: bigint,
    capacityBits: bigint,
    outputBlocks: bigint,
) => {
    if (
        rateBits < 1n ||
        rateBits > 2048n ||
        capacityBits < 1n ||
        capacityBits > 2048n
    )
        throw new RangeError('Invalid bounded sponge dimensions.');
    const rateSize = 1n << rateBits,
        capacitySize = 1n << capacityBits;
    if (outputBlocks < 0n || outputBlocks >= capacitySize)
        throw new RangeError('Insufficient distinct nonzero capacities.');
    const stateSize = rateSize * capacitySize;
    return {
        numerator: rateSize * outputBlocks * (outputBlocks + 1n),
        denominator: 2n * (stateSize - outputBlocks + 1n),
    };
};

export const compileFixedSpongeInitializationCensus = () => {
    // FIPS 202 Sections 5.2 and 6.2: KECCAK-p[1600,24], capacity 512.
    const capacityBits = 512n,
        rateBits = 1600n - capacityBits;
    const rateBytes = Number(rateBits / 8n);
    const matrices = compileCommonMatrixSamplingCensus();
    const gadgetCount = Number(matrices.fhePolynomialCount / 3n);
    if (BigInt(3 * gadgetCount) !== matrices.fhePolynomialCount)
        throw new Error('Incomplete fixed gadget-vector groups.');
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const sharingModulus =
        compileSmallLimbProofFieldCensus().modulus * 998244353n;
    const roles = Array.from({ length: gadgetCount }, (_, gadget) =>
        ['a', 'u', 'k'].map(
            (part): { label: string; degree: bigint; modulus: bigint } => ({
                label: `common-fhe-${part}-${gadget}`,
                degree,
                modulus: fixedModulusBfvInputs.ciphertextModulus,
            }),
        ),
    )
        .flat()
        .concat([
            { label: 'common-share', degree, modulus: sharingModulus },
            {
                label: 'common-auxiliary',
                degree: auxiliaryInputEncryptionParameters.degree,
                modulus: auxiliaryInputEncryptionParameters.modulus,
            },
        ]);
    const prefix = Buffer.from('synthetic-full-setup-witness/1');
    const extraSamplingBits =
        capacityBits / 2n +
        BigInt((matrices.coefficientCount - 1n).toString(2).length);
    const seeds = roles.map(({ label, degree: seedDegree, modulus }) => {
        const bytes = Buffer.from(label),
            length = Buffer.alloc(4);
        length.writeUInt32LE(bytes.length);
        const message = Buffer.concat([prefix, length, bytes]);
        if (message.length >= rateBytes)
            throw new Error('The fixed seed no longer fits one padded block.');
        const paddedInput = Buffer.alloc(200);
        message.copy(paddedInput);
        paddedInput[message.length] ^= 0x1f;
        paddedInput[rateBytes - 1] ^= 0x80;
        const outputBits = seedDegree * BigInt(matrices.bitsPerCoefficient);
        const maximumFiberSize =
            ((1n << BigInt(matrices.bitsPerCoefficient)) + modulus - 1n) /
            modulus;
        const fiberRandomBits =
            BigInt(maximumFiberSize.toString(2).length) + extraSamplingBits;
        return {
            label,
            message,
            paddedInput,
            outputBits,
            fiberRandomBits,
            outputBlocks: (outputBits + rateBits - 1n) / rateBits,
        };
    });
    if (
        new Set(seeds.map(({ paddedInput }) => paddedInput.toString('hex')))
            .size !== seeds.length
    )
        throw new Error('Fixed seeds alias after padding.');
    const outputBlocks = seeds.reduce(
        (total, seed) => total + seed.outputBlocks,
        0n,
    );
    const bound = staticSpongeConditioningBound(
        rateBits,
        capacityBits,
        outputBlocks,
    );
    const exponent = (numerator: bigint, denominator: bigint) => {
        let bits = 0;
        while (numerator << BigInt(bits + 1) <= denominator) bits++;
        return bits;
    };
    const capacitySamplingBound = {
        numerator: outputBlocks * (outputBlocks + 1n),
        denominator: 2n << capacityBits,
    };
    const fiberSamplingBound = {
        numerator: matrices.coefficientCount,
        denominator: 4n << extraSamplingBits,
    };
    let combinedNumerator = 0n,
        combinedDenominator = 1n;
    for (const value of [
        bound,
        capacitySamplingBound,
        fiberSamplingBound,
        {
            numerator: matrices.distanceUpperNumerator,
            denominator: matrices.distanceUpperDenominator,
        },
    ]) {
        combinedNumerator =
            combinedNumerator * value.denominator +
            value.numerator * combinedDenominator;
        combinedDenominator *= value.denominator;
    }
    return {
        seeds,
        rateBits,
        capacityBits,
        outputBlocks,
        conditioningBound: bound,
        capacitySamplingBound,
        fiberSamplingBound,
        extraSamplingBits,
        maximumFiberRandomBits: seeds.reduce(
            (maximum, seed) =>
                seed.fiberRandomBits > maximum ? seed.fiberRandomBits : maximum,
            0n,
        ),
        maximumSeedBytes: Math.max(
            ...seeds.map(({ message }) => message.length),
        ),
        conditioningFailureExponent: exponent(
            bound.numerator,
            bound.denominator,
        ),
        combinedInitializationFailureExponent: exponent(
            combinedNumerator,
            combinedDenominator,
        ),
    };
};
