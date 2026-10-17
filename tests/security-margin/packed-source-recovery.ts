import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { sourceMessageScale } from '#tests/encrypted-registration-source-model.js';
import {
    WordProgramBuilder,
    type Word,
} from '#tests/security-margin/word-program.js';

// A proof-only classical decoder with an owned auxiliary key. This is not
// a participant export or a public verifier capability. Failure has no
// consumable output; the enclosing reduction discards its partial writes.
export const buildPackedSourceRecoveryProgram = () => {
    const program = new WordProgramBuilder();
    const input = program.input('input'),
        key = program.input('key'),
        output = program.input('output'),
        scratch = program.input('scratch');
    const degree = program.input('degree'),
        auxiliaryDegree = program.input('auxiliary-degree'),
        stride = program.input('stride');
    const keyHalf = program.input('key-half-support'),
        sourceHalf = program.input('source-half-support');
    const modulus = auxiliaryInputEncryptionParameters.modulus,
        scale = sourceMessageScale;
    const lessEqual = (left: Word, right: Word) =>
        program.subtract(1n, program.less(right, left));
    program.require(program.less(0n, degree));
    program.require(lessEqual(degree, 65536n));
    program.require(
        program.equal(
            program.binary('bit-and', degree, program.subtract(degree, 1n)),
            0n,
        ),
    );
    program.require(program.less(0n, auxiliaryDegree));
    program.require(lessEqual(auxiliaryDegree, 4096n));
    program.require(
        program.equal(program.multiply(auxiliaryDegree, stride), degree),
    );
    program.require(program.less(0n, stride));
    program.require(
        program.equal(
            program.binary(
                'bit-and',
                auxiliaryDegree,
                program.subtract(auxiliaryDegree, 1n),
            ),
            0n,
        ),
    );
    program.require(program.less(0n, keyHalf));
    program.require(lessEqual(keyHalf, 128n));
    program.require(lessEqual(program.multiply(keyHalf, 2n), auxiliaryDegree));
    program.require(program.less(0n, sourceHalf));
    program.require(lessEqual(program.multiply(sourceHalf, 2n), degree));
    const keySupport = program.multiply(keyHalf, 2n);
    const keyList = scratch,
        residues = program.add(scratch, program.multiply(keySupport, 32n));
    const positive = program.copy(0n),
        negative = program.copy(0n),
        selected = program.copy(0n);
    program.range(auxiliaryDegree, (position) => {
        const value = program.readSpan(
            program.add(key, program.multiply(position, 2n)),
            2n,
        );
        program.require(program.less(value, 3n));
        program.when(program.less(0n, value), () => {
            program.require(program.less(selected, keySupport));
            const sign = program.equal(value, 2n);
            program.writeSpan(
                program.add(keyList, program.multiply(selected, 32n)),
                32n,
                program.add(program.multiply(position, 2n), sign),
            );
            program.when(
                sign,
                () => program.assign(negative, program.add(negative, 1n)),
                () => program.assign(positive, program.add(positive, 1n)),
            );
            program.assign(selected, program.add(selected, 1n));
        });
    });
    program.require(program.equal(positive, keyHalf));
    program.require(program.equal(negative, keyHalf));
    program.range(program.multiply(degree, 2n), (position) => {
        const record = program.readSpan(
            program.add(input, program.multiply(position, 48n)),
            48n,
        );
        const sign = program.binary('bit-and', record, 255n),
            magnitude = program.binary('shift-right', record, 8n);
        program.require(program.less(sign, 2n));
        program.require(lessEqual(magnitude, modulus / 2n));
        const value = program.copy(magnitude);
        program.when(sign, () => {
            program.require(program.less(0n, magnitude));
            program.assign(value, program.subtract(modulus, magnitude));
        });
        program.writeSpan(
            program.add(residues, program.multiply(position, 64n)),
            64n,
            value,
        );
    });
    const sourcePositive = program.copy(0n),
        sourceNegative = program.copy(0n);
    program.range(degree, (position) => {
        const phase = program.copy(
            program.readSpan(
                program.add(residues, program.multiply(position, 64n)),
                64n,
            ),
        );
        program.range(keySupport, (item) => {
            const entry = program.readSpan(
                program.add(keyList, program.multiply(item, 32n)),
                32n,
            );
            const shift = program.multiply(program.half(entry), stride),
                sign = program.copy(program.low(entry)),
                index = program.copy(0n);
            program.when(
                program.less(position, shift),
                () => {
                    program.assign(
                        index,
                        program.subtract(program.add(degree, position), shift),
                    );
                    program.assign(sign, program.subtract(1n, sign));
                },
                () => program.assign(index, program.subtract(position, shift)),
            );
            const value = program.readSpan(
                program.add(
                    residues,
                    program.multiply(program.add(degree, index), 64n),
                ),
                64n,
            );
            program.when(
                sign,
                () => {
                    program.when(
                        program.less(phase, value),
                        () =>
                            program.assign(
                                phase,
                                program.subtract(
                                    program.add(phase, modulus),
                                    value,
                                ),
                            ),
                        () =>
                            program.assign(
                                phase,
                                program.subtract(phase, value),
                            ),
                    );
                },
                () => {
                    program.assign(phase, program.add(phase, value));
                    program.when(lessEqual(modulus, phase), () =>
                        program.assign(phase, program.subtract(phase, modulus)),
                    );
                },
            );
        });
        const message = program.copy(0n);
        program.when(
            program.less(modulus / 2n, phase),
            () =>
                program.require(
                    lessEqual(program.subtract(modulus, phase), scale / 2n),
                ),
            () => {
                const remaining = program.copy(program.add(phase, scale / 2n));
                program.loop(
                    () => lessEqual(scale, remaining),
                    () => {
                        program.assign(
                            remaining,
                            program.subtract(remaining, scale),
                        );
                        program.assign(message, program.add(message, 1n));
                    },
                );
            },
        );
        program.require(program.less(message, 384n));
        // For 0 <= m < 384, floor(m/3) = floor(171*m/512).
        const errorWord = program.binary(
            'shift-right',
            program.multiply(message, 171n),
            9n,
        );
        const secretWord = program.subtract(
            message,
            program.multiply(errorWord, 3n),
        );
        program.when(program.equal(secretWord, 0n), () =>
            program.assign(sourceNegative, program.add(sourceNegative, 1n)),
        );
        program.when(program.equal(secretWord, 2n), () =>
            program.assign(sourcePositive, program.add(sourcePositive, 1n)),
        );
        program.writeSpan(
            program.add(output, program.multiply(position, 16n)),
            16n,
            secretWord,
        );
        program.writeSpan(
            program.add(
                output,
                program.multiply(program.add(degree, position), 16n),
            ),
            16n,
            errorWord,
        );
    });
    program.require(program.equal(sourcePositive, sourceHalf));
    program.require(program.equal(sourceNegative, sourceHalf));
    return program.finish({ output, count: program.multiply(degree, 2n) });
};

// The input scan has two polynomials. Each convolution item performs two
// reads, one half and one increment. Rounding subtracts a positive fixed
// scale at most floor((floor(q/2)+floor(scale/2))/scale) times, even on a
// malformed message later refused by the range or support checks.
export const packedSourceRecoveryBounds = (
    degree: bigint,
    auxiliaryDegree: bigint,
    keySupport: bigint,
) => {
    const maximumRoundings =
        (auxiliaryInputEncryptionParameters.modulus / 2n +
            sourceMessageScale / 2n) /
        sourceMessageScale;
    return {
        events:
            5n +
            3n * auxiliaryDegree +
            4n * keySupport +
            degree * (4n * keySupport + maximumRoundings + 11n),
        spanBits: 256n * degree + 2n * auxiliaryDegree + 32n * keySupport,
    };
};
