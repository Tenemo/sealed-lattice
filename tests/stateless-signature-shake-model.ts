import { compileAuthenticationFrameWork } from '#tests/authentication-work-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

type Work = Readonly<{
    hashCalls: bigint;
    inputBytes: bigint;
    outputBytes: bigint;
    permutations: bigint;
}>;
const sum = (terms: readonly (readonly [bigint, Work])[]): Work =>
    terms.reduce(
        (total, [count, value]) => ({
            hashCalls: total.hashCalls + count * value.hashCalls,
            inputBytes: total.inputBytes + count * value.inputBytes,
            outputBytes: total.outputBytes + count * value.outputBytes,
            permutations: total.permutations + count * value.permutations,
        }),
        { hashCalls: 0n, inputBytes: 0n, outputBytes: 0n, permutations: 0n },
    );

// FIPS 205 section 11.1, with the current application's actual pure-signature
// frames. Length separation here is not a claim for unrestricted FIPS messages.
export const compileStatelessSignatureShakeWork = () => {
    const parameters = compileStatelessSignatureWork(),
        n = parameters.nodeBytes;
    const hash = (inputBytes: bigint, outputBytes: bigint): Work => ({
        hashCalls: 1n,
        inputBytes,
        outputBytes,
        permutations: byteAlignedSpongePermutations(
            inputBytes,
            outputBytes,
            136n,
        ),
    });
    const fixed = {
        pseudorandomFunction: {
            ...hash(2n * n + 32n, n),
            addressTypes: [5, 6],
        },
        chainHash: { ...hash(2n * n + 32n, n), addressTypes: [0, 3] },
        parentHash: { ...hash(3n * n + 32n, n), addressTypes: [2, 3] },
        chainCompression: {
            ...hash(n + 32n + parameters.chains * n, n),
            addressTypes: [1],
        },
        forestCompression: {
            ...hash(n + 32n + parameters.forestTrees * n, n),
            addressTypes: [4],
        },
    };
    const keyGeneration = sum([
        [
            parameters.keyGeneration.pseudorandomFunction,
            fixed.pseudorandomFunction,
        ],
        [parameters.keyGeneration.chainHash, fixed.chainHash],
        [parameters.keyGeneration.parentHash, fixed.parentHash],
        [parameters.keyGeneration.chainCompression, fixed.chainCompression],
    ]);
    const roles = compileAuthenticationFrameWork().map((role) => {
        const randomization = hash(2n * n + role.frameBytes, n),
            messageHash = hash(
                3n * n + role.frameBytes,
                parameters.digestBytes,
            );
        const signingUpper = sum([
            [
                parameters.signing.pseudorandomFunction,
                fixed.pseudorandomFunction,
            ],
            [parameters.signing.chainHashUpper, fixed.chainHash],
            [parameters.signing.parentHash, fixed.parentHash],
            [parameters.signing.chainCompression, fixed.chainCompression],
            [parameters.signing.forestCompression, fixed.forestCompression],
            [parameters.signing.messageRandomization, randomization],
            [parameters.signing.messageHash, messageHash],
        ]);
        const verificationUpper = sum([
            [parameters.verification.chainHashUpper, fixed.chainHash],
            [parameters.verification.parentHash, fixed.parentHash],
            [parameters.verification.chainCompression, fixed.chainCompression],
            [
                parameters.verification.forestCompression,
                fixed.forestCompression,
            ],
            [parameters.verification.messageHash, messageHash],
        ]);
        return {
            purpose: role.purpose,
            frameBytes: role.frameBytes,
            randomization,
            messageHash,
            signingUpper,
            verificationUpper,
        };
    });
    return {
        fixed,
        keyGeneration,
        roles,
        ordinaryScreenUpper: sum([
            [1n, keyGeneration],
            ...roles.flatMap(
                (role) =>
                    [
                        [1n, role.signingUpper],
                        [1n, role.verificationUpper],
                    ] as const,
            ),
        ]),
    };
};
