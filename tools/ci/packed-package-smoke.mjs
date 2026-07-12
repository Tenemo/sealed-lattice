const { verifyPrivateVssShare } = await import('sealed-lattice');

if (typeof verifyPrivateVssShare !== 'function') {
    throw new Error('The packed private VSS verifier is not callable.');
}

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

if (
    verification.isValid !== false ||
    verification.refusedObjects[0]?.reasonCode !== 'setupParametersHashMismatch'
) {
    throw new Error(
        'The packed private VSS verifier did not execute the WASM rejection path.',
    );
}

console.log('Packed package WASM smoke test passed.');
