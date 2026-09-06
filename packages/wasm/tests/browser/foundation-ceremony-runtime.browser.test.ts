import { describe, expect, it } from 'vitest';

import { createFoundationCeremonyRuntimeLoader } from '../../src/foundation-ceremony-runtime.js';

const kernelUrl = new URL(
    '/packages/wasm/dist/sealed-lattice-kernel.wasm',
    window.location.origin,
);

describe('foundation ceremony runtime in Chromium', () => {
    it('executes the same scalar WASM bytes at both structural option-count boundaries', async () => {
        const runtime = await createFoundationCeremonyRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();

        for (const optionCount of [2, 20]) {
            const encoded = runtime.encodeManifest({
                displayTitle: 'Choose priorities',
                optionDefinitions: Array.from(
                    { length: optionCount },
                    (_unused, optionIndex) => ({
                        displayLabel: `Option ${String(optionIndex)}`,
                        optionIdentifier: `option-${String(optionIndex)}`,
                        optionIndex,
                    }),
                ),
            });
            expect(runtime.verifyManifest(encoded.canonicalBytes)).toEqual({
                isValid: true,
                value: { manifestHash: encoded.manifestHash },
            });
        }
    });
});
