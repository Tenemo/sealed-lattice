const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const publicApi = await import('sealed-lattice');
const {
    deriveThresholdParameters,
    deriveValidatedFirstValidOrder,
    verifyTranscriptCoreFixture,
} = publicApi;

assert(
    typeof verifyTranscriptCoreFixture === 'function',
    'Transcript-core fixture verifier must be exported as a function',
);
assert(
    typeof deriveThresholdParameters === 'function',
    'Threshold parameters calculator must be exported as a function',
);
assert(
    deriveThresholdParameters({ rosterSize: 10 }).privacyCorruptionBound === 3,
    'Threshold parameters calculator must be exported and deterministic',
);
assert(
    deriveValidatedFirstValidOrder({
        requiredContextHash: 'context',
        selectionPolicyHash: 'policy',
        expectedSelectionPolicyHash: 'policy',
        currentRecoveryEpochMap: {
            participant: {
                signerIdentity: 'participant',
                currentRecoveryEpoch: 0,
                currentDeviceEpoch: 0,
            },
        },
        objects: [
            {
                objectHash: 'candidate',
                objectType: 'TargetFinalityRecord',
                boardSequence: 1,
                boardPosition: 0,
                signerIdentity: 'participant',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextHash: 'context',
                isByteIdenticalRetransmission: false,
            },
        ],
    }).orderedObjects[0]?.objectHash === 'candidate',
    'First-valid ordering helper must be exported and deterministic',
);
const verification = await verifyTranscriptCoreFixture({
    kind: 'malformed-object',
    fixtureVersion: 1,
    caseName: 'packed-malformed-magic-smoke',
    canonicalBytesHex: '42414421',
    expectedErrorCode: 'MalformedMagic',
});
assert(
    verification.isValid === false &&
        verification.rejection?.code === 'MalformedMagic',
    'Packed transcript-core verifier did not reject malformed bytes as expected',
);

console.log('Packed package public API smoke test passed.');
