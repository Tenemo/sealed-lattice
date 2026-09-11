import { maximumFoundationCopiedBufferByteLength } from '@sealed-lattice/wasm';

import type { PollSpec } from '../src/poll-spec.js';

const optionCount = 10;
const textEncoder = new TextEncoder();
const canonicalManifestCommandResponseOverheadByteLength = 1 + 4 + 64;

export const maximumCanonicalManifestFixtureByteLength =
    maximumFoundationCopiedBufferByteLength -
    canonicalManifestCommandResponseOverheadByteLength;

export const createMaximumAcceptedPollSpec = (): PollSpec => {
    const options = Array.from(
        { length: optionCount },
        (_value, optionIndex) => `O${String(optionIndex)}`,
    );
    const displayLabelByteLength = options.reduce(
        (total, label) => total + textEncoder.encode(label).byteLength,
        0,
    );
    const canonicalManifestNonDisplayByteLength =
        30 +
        36 * optionCount +
        Array.from(
            { length: optionCount },
            (_value, optionIndex) => `option-${String(optionIndex)}`,
        ).reduce(
            (total, identifier) =>
                total + textEncoder.encode(identifier).byteLength,
            0,
        );

    return {
        options,
        question: 'Q'.repeat(
            maximumCanonicalManifestFixtureByteLength -
                canonicalManifestNonDisplayByteLength -
                displayLabelByteLength,
        ),
    };
};
