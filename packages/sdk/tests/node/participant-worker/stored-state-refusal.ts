import { expect } from 'vitest';

import { classifyFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';

// A stored state's codec refuses every proper prefix as local state loss,
// which stops a participant whose authority started, never as a pending
// cause such as the resource failure a RangeError reads as. A long state
// is checked at every length near either end and at evenly spaced lengths
// between.
export const expectEveryTruncationStops = (
    bytes: Uint8Array,
    decode: (prefix: Uint8Array) => unknown,
) => {
    const lengths = new Set<number>();
    for (let index = 0; index < Math.min(bytes.length, 512); index++)
        lengths.add(index).add(bytes.length - 1 - index);
    for (let step = 1; step < 128; step++)
        lengths.add(Math.floor((step * bytes.length) / 128));
    lengths.delete(bytes.length);
    for (const length of lengths) {
        let refusal: unknown;
        try {
            decode(bytes.subarray(0, length));
        } catch (error) {
            refusal = error;
        }
        const label = `${length} of ${bytes.length} bytes`;
        expect(refusal, label).toBeInstanceOf(Error);
        expect(classifyFailure(refusal, true), label).toEqual({
            status: 'stopped',
        });
    }
};
