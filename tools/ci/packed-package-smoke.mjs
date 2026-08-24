const { createCanonicalBoardPolicy, verifyCanonicalBoardPolicy } =
    await import('sealed-lattice');

if (
    typeof createCanonicalBoardPolicy !== 'function' ||
    typeof verifyCanonicalBoardPolicy !== 'function'
) {
    throw new Error('The packed canonical board-policy API is not callable.');
}

const canonicalBoardPolicy = await createCanonicalBoardPolicy({
    boardOriginIdentifier: 'https://board.example',
});
const verification = await verifyCanonicalBoardPolicy(
    canonicalBoardPolicy.canonicalBytes,
);

if (!verification.isValid) {
    throw new Error(
        'The packed canonical board-policy API did not execute the WASM acceptance path.',
    );
}

console.log('Packed package WASM smoke test passed.');
