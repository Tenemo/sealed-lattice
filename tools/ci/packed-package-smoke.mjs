const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const publicApi = await import('sealed-lattice');
const {
    deriveThresholdProfile,
    deriveValidatedFirstComeOrder,
    verifyTranscriptCoreFixture,
} = publicApi;
const expectedPublicKeys = [
    'deriveLifecycleLabels',
    'deriveThresholdProfile',
    'deriveValidatedFirstComeOrder',
    'evaluateActionCapability',
    'isActionCurrentForRecoveryEpoch',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyBoardConsistency',
    'verifyCastReceiptShell',
    'verifyCloseRecordShell',
    'verifyFirstComePolicy',
    'verifyRecoveryEpochUpdate',
    'verifyRosterManifestTranscript',
    'verifyTargetFinality',
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
    'verifyEvaluationReplayAttestationShell',
    'verifyTargetAcceptedRecordShell',
    'verifyTopKDecryptionShareShell',
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
assert(
    deriveValidatedFirstComeOrder({
        requiredContextDigest: 'context',
        selectionPolicyDigest: 'policy',
        expectedSelectionPolicyDigest: 'policy',
        currentRecoveryEpochMap: {
            participant: {
                signerIdentity: 'participant',
                currentRecoveryEpoch: 0,
                currentDeviceEpoch: 0,
            },
        },
        candidates: [
            {
                objectDigest: 'candidate',
                objectType: 'TargetFinalityRecord',
                boardSeq: 1,
                boardPosition: 0,
                signerIdentity: 'participant',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest: 'context',
                isByteIdenticalRetransmission: false,
            },
        ],
    }).orderedCandidates[0]?.objectDigest === 'candidate',
    'First-come ordering helper must be exported and deterministic',
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
