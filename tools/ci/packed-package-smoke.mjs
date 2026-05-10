const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const publicApi = await import('sealed-lattice');
const { deriveThresholdProfile, verifyTranscriptCoreFixture } = publicApi;
const expectedPublicKeys = [
    'deriveLifecycleLabels',
    'deriveThresholdProfile',
    'evaluateActionCapability',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyTranscriptCoreFixture',
];
const forbiddenPublicKeys = [
    'getShare',
    'exportShare',
    'exportSecretKey',
    'importSecretKey',
    'setSecretKey',
    'thresholdDecrypt',
    'partialDecrypt',
    'partialDecryptWithoutTarget',
    'decryptToFile',
    'decryptToString',
    'rawHEAdd',
    'rawHEMul',
    'rawHERelin',
    'rawHERotate',
    'rawNTT',
    'rawRNSLimbAccess',
    'setNoiseFloodSigma',
    'setSmudgingDistribution',
    'bootstrap',
    'decryptAggregateShare',
    'decryptComparisonBit',
    'decryptExactSum',
    'decryptIntermediateWire',
    'decryptRank',
];

assert(
    JSON.stringify(Object.keys(publicApi).sort()) ===
        JSON.stringify(expectedPublicKeys),
    'Packed package public exports changed unexpectedly',
);
for (const publicKey of forbiddenPublicKeys) {
    assert(
        !(publicKey in publicApi),
        `Packed package must not export ${publicKey}`,
    );
}

assert(
    typeof verifyTranscriptCoreFixture === 'function',
    'Transcript-core fixture verifier must be exported as a function',
);
assert(
    typeof deriveThresholdProfile === 'function',
    'Threshold profile calculator must be exported as a function',
);
assert(
    deriveThresholdProfile({ rosterSize: 20 }).privacyCorruptionBound === 6,
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
