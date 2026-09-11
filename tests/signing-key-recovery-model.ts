import assert from 'node:assert/strict';

import { compileAuthenticationFrameWork } from '#tests/authentication-work-model.js';
import { compileStatelessSignatureShakeWork } from '#tests/stateless-signature-shake-model.js';

type SignedFrame = Readonly<{
    publicKey: Uint8Array;
    context: Uint8Array;
    message: Uint8Array;
}>;
const equal = (left: Uint8Array, right: Uint8Array) =>
    Buffer.from(left).equals(right);

export const compileSigningKeyRecoveryWork = (priorFrames: bigint) => {
    const role = compileAuthenticationFrameWork().find(
            (value) => value.purpose === 'registration',
        )!,
        signing = compileStatelessSignatureShakeWork().roles.find(
            (value) => value.purpose === 'registration',
        )!.signingUpper;
    if (priorFrames < 0n || priorFrames >= 1n << (8n * role.messageBytes))
        throw new RangeError(
            'Fresh-frame search exceeds its fixed message subset.',
        );
    return {
        messageBytes: role.messageBytes,
        maximumCandidates: priorFrames + 1n,
        additionalSigningOracleQueries: 0n,
        localSigningEvaluations: 1n,
        localSigningWork: signing,
    };
};

// A reduction that already obtained a valid matching private key can choose
// a fresh frame from the fixed registration-message subset. It does not
// query the honest signing oracle to produce that fresh signature.
export const freshRecoveryMessage = (
    publicKey: Uint8Array,
    context: Uint8Array,
    log: readonly SignedFrame[],
) => {
    const width = Number(
        compileAuthenticationFrameWork().find(
            (role) => role.purpose === 'registration',
        )!.messageBytes,
    );
    const used = new Set(
        log
            .filter(
                (frame) =>
                    equal(frame.publicKey, publicKey) &&
                    equal(frame.context, context) &&
                    frame.message.length === width,
            )
            .map((frame) => Buffer.from(frame.message).toString('hex')),
    );
    const message = Buffer.alloc(width);
    let candidates = 1;
    while (used.has(message.toString('hex'))) {
        let carry = true;
        for (let index = message.length - 1; index >= 0 && carry; index--) {
            message[index] = (message[index] + 1) & 255;
            carry = message[index] === 0;
        }
        if (carry) throw new Error('The fixed message subset is exhausted.');
        candidates++;
    }
    assert.ok(candidates <= used.size + 1);
    return {
        message: Uint8Array.from(message),
        candidates,
        distinctPriorFrames: used.size,
    };
};

// Conditional key-recovery reduction: the candidate key and its target are
// fixed before two independent fresh challenge messages are sampled. Exact
// key recovery gives correct decryption. A wrong decoder can accidentally
// match the unused challenge message; that term must not be dropped.
export const keyRecoveryChallengeControl = () => {
    const messages = 4,
        halfUnitsPerDecoder = 2 * messages * messages * 2;
    const score = (decoder: readonly number[]) => {
        let successes = 0;
        for (let left = 0; left < messages; left++)
            for (let right = 0; right < messages; right++)
                for (let bit = 0; bit < 2; bit++) {
                    const plaintext = bit === 0 ? left : right,
                        decoded = decoder[plaintext];
                    const leftMatch = decoded === left,
                        rightMatch = decoded === right;
                    if (leftMatch === rightMatch) successes++;
                    else if (Number(rightMatch) === bit) successes += 2;
                }
        return successes;
    };
    const correct = score([0, 1, 2, 3]),
        denominator = 4 * halfUnitsPerDecoder;
    let smallestSlack = denominator,
        negativeBiasCases = 0;
    const controls = [];
    for (let encoded = 0; encoded < 5 ** messages; encoded++) {
        let remaining = encoded;
        const decoder = [];
        for (let index = 0; index < messages; index++) {
            decoder.push(remaining % 5);
            remaining = Math.floor(remaining / 5);
        }
        const wrong = score(decoder);
        for (let recovered = 0; recovered <= 4; recovered++) {
            const success = recovered * correct + (4 - recovered) * wrong;
            // p <= 2*(Pr[guess=bit]-1/2) + 1/|message space|.
            const right = 2 * success - denominator + denominator / messages,
                left = (recovered * denominator) / 4,
                slack = right - left;
            assert.ok(slack >= 0);
            smallestSlack = Math.min(smallestSlack, slack);
            if (2 * success < denominator) negativeBiasCases++;
        }
        if (
            encoded === 0 ||
            decoder.every((value) => value === 4) ||
            decoder.every((value, index) => value === (index ^ 1))
        )
            controls.push({ decoder, wrongHalfUnits: wrong });
    }
    assert.equal(smallestSlack, 0);
    assert.ok(negativeBiasCases > 0);
    return {
        messages,
        decoders: 5 ** messages,
        recoveryWeights: 5,
        halfUnitsPerDecoder,
        correctHalfUnits: correct,
        denominator,
        smallestSlack,
        negativeBiasCases,
        controls,
    };
};
