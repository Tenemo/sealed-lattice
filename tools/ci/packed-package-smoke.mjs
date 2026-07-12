const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const assertImportIsRefused = async ({ specifier, expectedErrorCode }) => {
    try {
        await import(specifier);
    } catch (error) {
        assert(
            error instanceof Error &&
                'code' in error &&
                error.code === expectedErrorCode,
            `Importing ${specifier} failed with an unexpected error: ${String(error)}`,
        );
        return;
    }

    throw new Error(`Production package unexpectedly exposed ${specifier}`);
};

const publicApi = await import('sealed-lattice');
const {
    deriveThresholdParameters,
    deriveValidatedFirstValidOrder,
    validatePollSpec,
    verifyPrivateVssShare,
} = publicApi;

await Promise.all([
    assertImportIsRefused({
        specifier: 'sealed-lattice/dist/internal/transcript-core-bridge.js',
        expectedErrorCode: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    }),
    assertImportIsRefused({
        specifier: 'sealed-lattice/package.json',
        expectedErrorCode: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    }),
    assertImportIsRefused({
        specifier: '@sealed-lattice/protocol',
        expectedErrorCode: 'ERR_MODULE_NOT_FOUND',
    }),
    assertImportIsRefused({
        specifier: '@sealed-lattice/wasm',
        expectedErrorCode: 'ERR_MODULE_NOT_FOUND',
    }),
]);

assert(
    typeof verifyPrivateVssShare === 'function',
    'Private VSS verifier must be exported as a function',
);
assert(
    typeof deriveThresholdParameters === 'function',
    'Threshold parameters calculator must be exported as a function',
);
assert(
    typeof validatePollSpec === 'function',
    'Poll specification validator must be exported as a function',
);
const pollValidation = validatePollSpec({
    pollId: 'board-election-2026',
    question: 'Which proposal should be adopted?',
    options: Array.from(
        { length: 20 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
    topOptionCount: 5,
});
assert(
    pollValidation.isValid === true &&
        pollValidation.normalized?.options.length === 20 &&
        pollValidation.normalized.topOptionCount === 5,
    `README poll example failed validation: ${JSON.stringify(pollValidation)}`,
);
assert(
    deriveThresholdParameters({ rosterSize: 10 }).privacyCorruptionBound === 3,
    'Threshold parameters calculator must be exported and deterministic',
);
assert(
    deriveValidatedFirstValidOrder({
        requiredContextHash: 'context',
        selectionPolicyHash: 'policy',
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
const verification = await verifyPrivateVssShare({
    setupContext: {
        ceremonyId: 'packed-package-smoke',
        manifestHash: '0'.repeat(128),
        rosterHash: '1'.repeat(128),
        setupParametersHash: '2'.repeat(128),
        setupEpoch: 'packed-package-smoke',
    },
    publicMatrixSeedHash: '3'.repeat(128),
    sourceTrusteeCoefficientCommitmentRecord: {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
    },
    sourceTrusteeCoefficientCommitmentMaterialRecords: [],
    privateEnvelope: {
        objectType: 'PrivateVssShareEnvelope',
    },
});
assert(
    verification.isValid === false &&
        verification.refusedObjects[0]?.reasonCode ===
            'setupParametersHashMismatch',
    'Packed private VSS verifier did not reject mismatched setup parameters as expected',
);

console.log('Packed package public API smoke test passed.');
