const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const publicApi = await import('sealed-lattice');
const { deriveThresholdProfile, verifyTranscriptCoreFixture } = publicApi;

assert(
    typeof verifyTranscriptCoreFixture === 'function',
    'Transcript-core fixture verifier must be exported as a function',
);
assert(
    typeof deriveThresholdProfile === 'function',
    'Threshold profile calculator must be exported as a function',
);
assert(
    deriveThresholdProfile({ n: 20 }).cPriv === 6,
    'Threshold profile calculator must be exported and deterministic',
);
const verification = await verifyTranscriptCoreFixture({
    kind: 'malformed-object',
    fixtureVersion: 1,
    caseName: 'packed-malformed-magic-smoke',
    canonicalBytesHex: '42414421',
    expectedErrorCode: 'MalformedMagic',
});
assert(
    verification.label === 'TranscriptCoreRejected' &&
        verification.rejection?.code === 'MalformedMagic',
    'Packed transcript-core verifier did not reject malformed bytes as expected',
);

console.log('Packed package public API smoke test passed.');
