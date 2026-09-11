import {
    authenticationContext,
    compileAuthenticationFrameWork,
    type AuthenticationPurpose,
} from '#tests/authentication-work-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

type Work = Readonly<{
    hashCalls: bigint;
    inputBytes: bigint;
    outputBytes: bigint;
    permutations: bigint;
}>;

// Candidate FIPS context: fixed purpose, one delimiter and the public seed
// taken from the expected verification key. No caller-chosen label is added
// to the signature carrier.
export const labelledSignatureContext = (
    purpose: AuthenticationPurpose,
    publicSeed: Uint8Array,
) => {
    const parameters = compileStatelessSignatureWork();
    if (publicSeed.length !== Number(parameters.nodeBytes))
        throw new RangeError('Wrong public-seed width.');
    const context = Buffer.concat([
        Buffer.from(authenticationContext(purpose)),
        Buffer.from([0]),
        publicSeed,
    ]);
    if (context.length > 255)
        throw new RangeError('FIPS signature context too long.');
    return context;
};

// Public byte-domain routing used by the ideal-function argument. Returning
// no route leaves an arbitrary XOF input in the independent base domain.
export const labelledSignaturePrfRoute = (input: Uint8Array) => {
    const seedBytes = Number(compileStatelessSignatureWork().nodeBytes);
    if (input.length === 2 * seedBytes + 32) {
        const type = new DataView(
            input.buffer,
            input.byteOffset,
            input.byteLength,
        ).getUint32(seedBytes + 16, false);
        if (type === 5 || type === 6)
            return {
                kind: 'secret-element' as const,
                publicSeed: new Uint8Array(input.subarray(0, seedBytes)),
                secretOffset: seedBytes + 32,
            };
    }
    for (const role of compileAuthenticationFrameWork()) {
        const purpose = Buffer.from(role.context),
            contextBytes = purpose.length + 1 + seedBytes;
        if (
            input.length !==
            2 * seedBytes + 2 + contextBytes + Number(role.messageBytes)
        )
            continue;
        const start = 2 * seedBytes;
        if (input[start] !== 0 || input[start + 1] !== contextBytes) continue;
        const context = start + 2;
        if (
            !purpose.every((byte, index) => input[context + index] === byte) ||
            input[context + purpose.length] !== 0
        )
            continue;
        const label = context + purpose.length + 1;
        return {
            kind: 'message-randomization' as const,
            publicSeed: new Uint8Array(
                input.subarray(label, label + seedBytes),
            ),
            secretOffset: 0,
        };
    }
    return undefined;
};
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
// frames and the candidate public-seed context suffix. Length separation here
// is not a claim for unrestricted FIPS messages or current participant state.
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
        const frameBytes = role.frameBytes + 1n + n;
        const randomization = hash(2n * n + frameBytes, n),
            messageHash = hash(3n * n + frameBytes, parameters.digestBytes);
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
            frameBytes,
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
