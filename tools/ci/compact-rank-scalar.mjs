/** @param {WebAssembly.Module} module */
export const createCompactRankVerifier = async (module) => {
    const instance = await WebAssembly.instantiate(module, {});
    const {
        memory,
        rank_screen_input: input,
        rank_screen_verify: verify,
    } = instance.exports;
    if (
        !(memory instanceof WebAssembly.Memory) ||
        typeof input !== 'function' ||
        typeof verify !== 'function'
    )
        throw new Error('The compact rank verifier is missing its screen ABI.');
    return {
        /** @param {Uint8Array} bytes */
        verify(bytes) {
            const pointer = /** @type {number} */ (input(bytes.length));
            if (!pointer)
                throw new Error(
                    'The compact rank fixture exceeds its input buffer.',
                );
            new Uint8Array(memory.buffer, pointer, bytes.length).set(bytes);
            const result = /** @type {number} */ (verify());
            if (!Number.isInteger(result) || result < 0 || result > 7)
                throw new Error(
                    'The compact rank verifier returned an unknown refusal.',
                );
            return {
                accepted: result === 0,
                refusal: [
                    undefined,
                    'Statement',
                    'Encoding',
                    'Context',
                    'Authentication',
                    'Relation',
                    'Sumcheck',
                    'Opening',
                ][result],
            };
        },
        memoryBytes: () => memory.buffer.byteLength,
    };
};
