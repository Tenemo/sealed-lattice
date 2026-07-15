import { vi } from 'vitest';

const decodeCanonicalHex = (
    hexEncodedBytes: string,
    valueIndex: number,
): Uint8Array => {
    if (
        hexEncodedBytes.length % 2 !== 0 ||
        !/^[0-9a-f]*$/u.test(hexEncodedBytes)
    ) {
        throw new TypeError(
            `Deterministic Web Crypto value ${String(valueIndex)} must be lowercase canonical hex.`,
        );
    }

    return Uint8Array.from(
        { length: hexEncodedBytes.length / 2 },
        (_, byteIndex) =>
            Number.parseInt(
                hexEncodedBytes.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
    );
};

export const withDeterministicWebCryptoRandomness = async <Result>(
    orderedRandomValuesHex: readonly string[],
    operation: () => Promise<Result>,
): Promise<Result> => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error('The deterministic fixture requires Web Crypto.');
    }
    const orderedRandomValues = orderedRandomValuesHex.map(
        (hexEncodedBytes, valueIndex) =>
            decodeCanonicalHex(hexEncodedBytes, valueIndex),
    );
    let nextRandomValueIndex = 0;
    const deterministicGetRandomValues: Crypto['getRandomValues'] = <
        ArrayType extends ArrayBufferView | null,
    >(
        destination: ArrayType,
    ): ArrayType => {
        if (!(destination instanceof Uint8Array)) {
            throw new TypeError(
                'The deterministic fixture only supports Uint8Array destinations.',
            );
        }
        const nextRandomValue = orderedRandomValues[nextRandomValueIndex];
        if (nextRandomValue === undefined) {
            throw new Error(
                'The operation requested more Web Crypto randomness than the fixture supplied.',
            );
        }
        if (nextRandomValue.byteLength !== destination.byteLength) {
            throw new Error(
                `The operation requested ${String(destination.byteLength)} random bytes, but fixture value ${String(nextRandomValueIndex)} contains ${String(nextRandomValue.byteLength)} bytes.`,
            );
        }
        destination.set(nextRandomValue);
        nextRandomValueIndex += 1;

        return destination;
    };
    const getRandomValuesSpy = vi
        .spyOn(cryptoProvider, 'getRandomValues')
        .mockImplementation(deterministicGetRandomValues);

    try {
        const result = await operation();
        if (nextRandomValueIndex !== orderedRandomValues.length) {
            throw new Error(
                `The operation consumed ${String(nextRandomValueIndex)} of ${String(orderedRandomValues.length)} deterministic Web Crypto values.`,
            );
        }

        return result;
    } finally {
        getRandomValuesSpy.mockRestore();
        for (const randomValue of orderedRandomValues) {
            randomValue.fill(0);
        }
    }
};
