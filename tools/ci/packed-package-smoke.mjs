const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const expectedPublicKeys = [];
const publicApi = await import('sealed-lattice');

assert(
    JSON.stringify(Object.keys(publicApi).sort()) ===
        JSON.stringify(expectedPublicKeys),
    'Packed package public exports changed unexpectedly',
);

console.log('Packed package public API smoke test passed.');
