// Integer-ring algebra for a linear transition between independent secrets.
// This model has no key-distribution, proof, or ciphertext-acceptance claim.

export type IntegerRingElement = readonly bigint[];
type RingVector = readonly IntegerRingElement[];

type AcyclicKeyTransitionParameters = Readonly<{
    ciphertextModulus: bigint;
    decompositionBase: bigint;
    polynomialModulusDegree: number;
    specialModulus: bigint;
}>;

export type AcyclicKeyTransitionKey = Readonly<{
    commonVector: RingVector;
    sourceVector: RingVector;
    transitionVector: RingVector;
}>;

export const compileAcyclicKeyTransitionModel = (
    parameters: AcyclicKeyTransitionParameters,
) => {
    const {
        ciphertextModulus,
        decompositionBase,
        polynomialModulusDegree,
        specialModulus,
    } = parameters;
    if (
        polynomialModulusDegree < 2 ||
        !Number.isSafeInteger(polynomialModulusDegree) ||
        (polynomialModulusDegree & (polynomialModulusDegree - 1)) !== 0 ||
        ciphertextModulus < 3n ||
        specialModulus < 3n ||
        ciphertextModulus % 2n !== 1n ||
        specialModulus % 2n !== 1n ||
        decompositionBase < 2n
    ) {
        throw new RangeError('Invalid integer-ring transition parameters.');
    }
    const extendedModulus = ciphertextModulus * specialModulus;
    const gadget: bigint[] = [];
    for (let power = 1n; power < ciphertextModulus; power *= decompositionBase)
        gadget.push(power);

    const residue = (value: bigint, modulus: bigint): bigint =>
        ((value % modulus) + modulus) % modulus;
    const centered = (value: bigint, modulus: bigint): bigint => {
        const reduced = residue(value, modulus);
        return reduced > modulus / 2n ? reduced - modulus : reduced;
    };
    const element = (value: IntegerRingElement): IntegerRingElement => {
        if (value.length !== polynomialModulusDegree)
            throw new RangeError('The ring element has the wrong degree.');
        return value;
    };
    const vector = (value: RingVector): RingVector => {
        if (value.length !== gadget.length)
            throw new RangeError('The ring vector has the wrong length.');
        value.forEach(element);
        return value;
    };
    const zero = (): bigint[] =>
        Array.from({ length: polynomialModulusDegree }, () => 0n);
    const add = (
        left: IntegerRingElement,
        right: IntegerRingElement,
    ): bigint[] => {
        element(right);
        return element(left).map((value, index) => value + right[index]);
    };
    const scale = (value: IntegerRingElement, factor: bigint): bigint[] =>
        element(value).map((coefficient) => coefficient * factor);
    const subtract = (
        left: IntegerRingElement,
        right: IntegerRingElement,
    ): bigint[] => add(left, scale(right, -1n));
    const multiply = (
        left: IntegerRingElement,
        right: IntegerRingElement,
    ): bigint[] => {
        element(left);
        element(right);
        const result = zero();
        for (let row = 0; row < polynomialModulusDegree; row += 1)
            for (
                let column = 0;
                column < polynomialModulusDegree;
                column += 1
            ) {
                const exponent = row + column;
                const position = exponent % polynomialModulusDegree;
                result[position] =
                    result[position] +
                    (exponent >= polynomialModulusDegree ? -1n : 1n) *
                        left[row] *
                        right[column];
            }
        return result;
    };
    const normalize = (value: IntegerRingElement, modulus: bigint): bigint[] =>
        element(value).map((coefficient) => residue(coefficient, modulus));
    const externalProduct = (
        value: IntegerRingElement,
        values: RingVector,
    ): bigint[] => {
        vector(values);
        return gadget.reduce(
            (sum, power, index) =>
                add(
                    sum,
                    multiply(
                        element(value).map(
                            (coefficient) =>
                                (residue(coefficient, ciphertextModulus) /
                                    power) %
                                decompositionBase,
                        ),
                        values[index],
                    ),
                ),
            zero(),
        );
    };
    const modulusDown = (value: IntegerRingElement) => {
        const lifted = element(value).map((coefficient) =>
            centered(coefficient, extendedModulus),
        );
        const rounded = lifted.map((coefficient) =>
            coefficient < 0n
                ? -((-coefficient + specialModulus / 2n) / specialModulus)
                : (coefficient + specialModulus / 2n) / specialModulus,
        );
        return {
            remainder: subtract(scale(rounded, specialModulus), lifted),
            value: normalize(rounded, ciphertextModulus),
        };
    };

    const contribution = (
        commonVector: RingVector,
        sourceSecret: IntegerRingElement,
        destinationSecret: IntegerRingElement,
        sourceErrors: RingVector,
        transitionErrors: RingVector,
    ): AcyclicKeyTransitionKey => {
        vector(commonVector);
        vector(sourceErrors);
        vector(transitionErrors);
        return {
            commonVector,
            sourceVector: commonVector.map((common, index) =>
                normalize(
                    subtract(
                        sourceErrors[index],
                        multiply(sourceSecret, common),
                    ),
                    extendedModulus,
                ),
            ),
            transitionVector: commonVector.map((common, index) =>
                normalize(
                    add(
                        subtract(
                            transitionErrors[index],
                            multiply(destinationSecret, common),
                        ),
                        scale(sourceSecret, specialModulus * gadget[index]),
                    ),
                    extendedModulus,
                ),
            ),
        };
    };

    const apply = (
        key: AcyclicKeyTransitionKey,
        ciphertext: readonly [
            IntegerRingElement,
            IntegerRingElement,
            IntegerRingElement,
        ],
    ) => {
        const sourceProduct = modulusDown(
            externalProduct(ciphertext[2], key.sourceVector),
        );
        const transitionProduct = modulusDown(
            add(
                scale(ciphertext[1], specialModulus),
                externalProduct(ciphertext[2], key.transitionVector),
            ),
        );
        const constantProduct = modulusDown(
            externalProduct(transitionProduct.value, key.transitionVector),
        );
        const linearProduct = modulusDown(
            externalProduct(transitionProduct.value, key.commonVector),
        );
        return {
            constant: normalize(
                add(ciphertext[0], constantProduct.value),
                ciphertextModulus,
            ),
            linear: normalize(
                subtract(linearProduct.value, sourceProduct.value),
                ciphertextModulus,
            ),
            sourceProduct,
            transitionProduct,
            constantProduct,
            linearProduct,
        };
    };

    const errorBound = (
        sourceSecretOneNormBound: bigint,
        destinationSecretOneNormBound: bigint,
        keyErrorMaximumNormBound: bigint,
    ) => {
        const externalError =
            BigInt(gadget.length * polynomialModulusDegree) *
            (decompositionBase - 1n) *
            keyErrorMaximumNormBound;
        const scaledBound =
            (sourceSecretOneNormBound + destinationSecretOneNormBound + 1n) *
                externalError +
            ((sourceSecretOneNormBound +
                2n * destinationSecretOneNormBound +
                1n) *
                (specialModulus - 1n)) /
                2n;
        return {
            scaledBound,
            transitionErrorMaximumNormBound: scaledBound / specialModulus,
        };
    };

    return {
        add,
        apply,
        centered,
        contribution,
        errorBound,
        extendedModulus,
        externalProduct,
        gadget,
        normalize,
        scale,
        subtract,
        zero,
    };
};
