const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const expectedPublicKeys = [
    'deriveLifecycleLabels',
    'deriveThresholdProfile',
    'evaluateActionCapability',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyTranscriptCoreFixture',
];
const publicApi = await import('sealed-lattice');

assert(
    JSON.stringify(Object.keys(publicApi).sort()) ===
        JSON.stringify(expectedPublicKeys),
    'Packed package public exports changed unexpectedly',
);
assert(
    typeof publicApi.verifyTranscriptCoreFixture === 'function',
    'Transcript-core fixture verifier must be exported as a function',
);
assert(
    publicApi.deriveThresholdProfile({ n: 20 }).cPriv === 6,
    'Threshold profile calculator must be exported and deterministic',
);
const verification = await publicApi.verifyTranscriptCoreFixture({
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
