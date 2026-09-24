import assert from 'node:assert/strict';

interface ReleaseObservation {
    entropyBytes: number;
    entropyCalls: number;
    entropyByModule: Record<string, number>;
    webCryptoRandomBytes: number;
    webCryptoRandomCalls: number;
    keyGenerationCalls: number;
    operationCounts: Record<string, number>;
    operations: { operation: number; status: number }[];
}

// Evidence assertions only: this consumes an observer trace, not protocol
// bytes, and creates no verified release or participant capability.
export function assertCompletedReleaseObservation(
    observation: ReleaseObservation,
    bodyRecordCount?: number,
): void {
    for (const count of [
        observation.entropyBytes,
        observation.entropyCalls,
        observation.webCryptoRandomBytes,
        observation.webCryptoRandomCalls,
        observation.keyGenerationCalls,
    ])
        assert.equal(count, 0, 'Completed restore accessed randomness.');
    assert.deepEqual(observation.entropyByModule, {});
    assert.deepEqual(
        observation.operations.map(({ operation, status }) => [
            operation,
            status,
        ]),
        [
            [6, 0],
            [4, 0],
        ],
        'Completed restore changed the release operation sequence.',
    );
    const counts = observation.operationCounts;
    assert.deepEqual(Object.keys(counts).sort(), ['3', '4', '6']);
    assert.equal(counts['6'], 1);
    assert.equal(counts['4'], 1);
    assert.ok(Number.isSafeInteger(counts['3']) && counts['3'] > 0);
    if (bodyRecordCount !== undefined)
        assert.equal(counts['3'], bodyRecordCount);
}
