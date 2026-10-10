const wordRadix = 1n << 64n;
const reductionOffset = 133n;
const prothWitness = 7n;
const cubicNonresidue = 2n;
const transformOrder = 1n << 20n;

const exponentiate = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) !== 0n) result = (result * base) % modulus;
        base = (base * base) % modulus;
    }
    return result;
};

export const compileSmallLimbProofFieldCensus = () => {
    const oddFactor = wordRadix - reductionOffset;
    const modulus = oddFactor * wordRadix + 1n;
    if (
        oddFactor <= 0n ||
        oddFactor >= wordRadix ||
        oddFactor % 2n !== 1n ||
        exponentiate(prothWitness, (modulus - 1n) / 2n, modulus) !==
            modulus - 1n
    )
        throw new Error('The small-limb field failed its Proth certificate.');
    if (
        modulus % 3n !== 1n ||
        exponentiate(cubicNonresidue, (modulus - 1n) / 3n, modulus) === 1n
    )
        throw new Error('The cubic extension is not certified irreducible.');
    const transformRoot = exponentiate(
        prothWitness,
        (modulus - 1n) / transformOrder,
        modulus,
    );
    if (
        exponentiate(transformRoot, transformOrder, modulus) !== 1n ||
        exponentiate(transformRoot, transformOrder / 2n, modulus) === 1n
    )
        throw new Error('The transform root has the wrong order.');
    const modulusBitLength = BigInt(modulus.toString(2).length);
    const packedFieldElementByteLength = (modulusBitLength + 7n) / 8n;
    return {
        cubicNonresidue,
        extensionDegree: 3n,
        modulus,
        modulusBitLength,
        oddFactor,
        packedExtensionElementByteLength: 3n * packedFieldElementByteLength,
        packedFieldElementByteLength,
        prothWitness,
        reductionOffset,
        transformOrder,
        transformRoot,
        wordRadix,
    };
};
