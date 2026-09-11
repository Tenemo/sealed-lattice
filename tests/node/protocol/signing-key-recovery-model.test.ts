import { describe, expect, it } from 'vitest';

import {
    freshRecoveryMessage,
    keyRecoveryChallengeControl,
    compileSigningKeyRecoveryWork,
} from '#tests/signing-key-recovery-model.js';

const message = (value: number) => {
    const bytes = Buffer.alloc(64);
    bytes.writeUInt32BE(value, 60);
    return bytes;
};
describe('Signing vault key-recovery boundary', () => {
    it('charges local forgery work without inventing another oracle response', () => {
        const value = compileSigningKeyRecoveryWork(15n);
        expect(value.messageBytes).toBe(64n);
        expect(value.maximumCandidates).toBe(16n);
        expect(value.additionalSigningOracleQueries).toBe(0n);
        expect(value.localSigningEvaluations).toBe(1n);
        expect(value.localSigningWork.hashCalls).toBeGreaterThan(0n);
        expect(() => compileSigningKeyRecoveryWork(-1n)).toThrow(RangeError);
        expect(() => compileSigningKeyRecoveryWork(1n << 512n)).toThrow(
            RangeError,
        );
    });
    it('selects a fresh frame for the exact credential and context', () => {
        const publicKey = Buffer.alloc(64, 3),
            context = Buffer.from('current-purpose'),
            otherKey = Buffer.alloc(64, 4),
            otherContext = Buffer.from('other-purpose');
        const log = [
            ...[0, 1, 2, 255, 256].map((value) => ({
                publicKey,
                context,
                message: message(value),
            })),
            { publicKey, context: otherContext, message: message(3) },
            { publicKey: otherKey, context, message: message(3) },
            { publicKey, context, message: message(0) },
        ];
        expect(freshRecoveryMessage(publicKey, context, log)).toEqual({
            message: Uint8Array.from(message(3)),
            candidates: 4,
            distinctPriorFrames: 5,
        });
        expect(freshRecoveryMessage(publicKey, context, [])).toEqual({
            message: Uint8Array.from(message(0)),
            candidates: 1,
            distinctPriorFrames: 0,
        });
    });
    it('handles carry across message bytes without replacing a prior frame', () => {
        const publicKey = Buffer.alloc(64, 3),
            context = Buffer.from('purpose');
        const log = Array.from({ length: 257 }, (_, value) => ({
            publicKey,
            context,
            message: message(value),
        }));
        expect(freshRecoveryMessage(publicKey, context, log)).toEqual({
            message: Uint8Array.from(message(257)),
            candidates: 258,
            distinctPriorFrames: 257,
        });
    });
    it('includes the unused-message collision term for every possible wrong decoder', () => {
        const value = keyRecoveryChallengeControl();
        expect(value.decoders).toBe(625);
        expect(value.recoveryWeights).toBe(5);
        expect(value.correctHalfUnits).toBe(56);
        expect(value.halfUnitsPerDecoder).toBe(64);
        expect(value.smallestSlack).toBe(0);
        expect(value.negativeBiasCases).toBeGreaterThan(0);
        expect(
            value.controls.find(
                (control) => control.decoder.join(',') === '1,0,3,2',
            )?.wrongHalfUnits,
        ).toBe(24);
    });
});
